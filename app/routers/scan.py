"""URL Scanning Router - Phishing Detection"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.models import ScanHistory
from app.schemas.scan import ScanRequest, ScanResponse, ScanHistoryResponse, OSINTData
from app.services.ai_engine import phishing_predictor
from app.services.osint import collect_osint_data, get_osint_summary

logger = logging.getLogger(__name__)

router = APIRouter()


def determine_threat_type(is_phishing: bool, confidence: float, url: str) -> Optional[str]:
    """Determine threat type based on URL patterns"""
    if not is_phishing:
        return None
    
    url_lower = url.lower()
    
    # Check for specific threat patterns
    if any(keyword in url_lower for keyword in ['login', 'signin', 'account', 'verify', 'update']):
        return "credential_theft"
    elif any(keyword in url_lower for keyword in ['download', 'install', 'exe', 'apk']):
        return "malware"
    elif any(keyword in url_lower for keyword in ['prize', 'win', 'claim', 'gift']):
        return "scam"
    elif any(keyword in url_lower for keyword in ['bank', 'paypal', 'payment']):
        return "financial_fraud"
    else:
        return "phishing"


@router.post("", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def scan_url(
    scan_request: ScanRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Scan a URL for phishing detection
    
    - **url**: URL to scan (must be valid HTTP/HTTPS URL)
    - **include_osint**: Include OSINT data enrichment (default: True)
    
    Returns prediction with confidence score, threat type, and optional OSINT data
    """
    
    logger.info(f"Scanning URL: {scan_request.url}")
    
    try:
        # Use PhishingPredictor service for prediction
        url_str = str(scan_request.url)
        prediction_result = phishing_predictor.predict(url_str)
        
        is_phishing = prediction_result['is_phishing']
        confidence_score = prediction_result['confidence_score']
        
        # Determine threat type
        threat_type = determine_threat_type(is_phishing, confidence_score, url_str)
        
        logger.info(f"Prediction: {'PHISHING' if is_phishing else 'SAFE'} (Confidence: {confidence_score:.2f}%)")
        
        # Collect OSINT data if requested
        osint_data = None
        if scan_request.include_osint:
            try:
                logger.info("Collecting OSINT data...")
                osint_full = collect_osint_data(url_str)
                osint_summary = get_osint_summary(osint_full)
                osint_data = OSINTData(**osint_summary)
                logger.info(f"[OK] OSINT data collected: {osint_summary.get('server_location')}")
            except Exception as e:
                logger.warning(f"Failed to collect OSINT data: {e}")
                # Continue without OSINT data
        
        # Save to database
        scan_record = ScanHistory(
            url=str(scan_request.url),
            is_phishing=is_phishing,
            confidence_score=round(confidence_score, 2),
            threat_type=threat_type,
            scanned_at=datetime.utcnow(),
            user_id=None  # TODO: Add user_id when authentication is implemented
        )
        
        db.add(scan_record)
        await db.commit()
        await db.refresh(scan_record)
        
        logger.info(f"Scan result saved to database (ID: {scan_record.id})")
        
        return ScanResponse(
            id=scan_record.id,
            url=scan_record.url,
            is_phishing=scan_record.is_phishing,
            confidence_score=scan_record.confidence_score,
            threat_type=scan_record.threat_type,
            scanned_at=scan_record.scanned_at,
            user_id=scan_record.user_id,
            osint=osint_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning URL: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to scan URL: {str(e)}"
        )


@router.get("/history", response_model=ScanHistoryResponse)
async def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan history
    
    - **limit**: Maximum number of results (default: 50, max: 100)
    - **offset**: Number of results to skip (default: 0)
    """
    
    # Validate parameters
    if limit > 100:
        limit = 100
    if offset < 0:
        offset = 0
    
    try:
        # Get total count
        count_query = select(ScanHistory)
        result = await db.execute(count_query)
        total = len(result.scalars().all())
        
        # Get paginated results
        query = select(ScanHistory).order_by(desc(ScanHistory.scanned_at)).limit(limit).offset(offset)
        result = await db.execute(query)
        scans = result.scalars().all()
        
        logger.info(f"Retrieved {len(scans)} scan records (offset: {offset}, limit: {limit})")
        
        return ScanHistoryResponse(
            total=total,
            scans=[
                ScanResponse(
                    id=scan.id,
                    url=scan.url,
                    is_phishing=scan.is_phishing,
                    confidence_score=scan.confidence_score,
                    threat_type=scan.threat_type,
                    scanned_at=scan.scanned_at,
                    user_id=scan.user_id
                )
                for scan in scans
            ]
        )
        
    except Exception as e:
        logger.error(f"Error retrieving scan history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan history"
        )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_by_id(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get specific scan result by ID"""
    
    try:
        query = select(ScanHistory).where(ScanHistory.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
        
        return ScanResponse(
            id=scan.id,
            url=scan.url,
            is_phishing=scan.is_phishing,
            confidence_score=scan.confidence_score,
            threat_type=scan.threat_type,
            scanned_at=scan.scanned_at,
            user_id=scan.user_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving scan {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan"
        )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Delete a scan record"""
    
    try:
        query = select(ScanHistory).where(ScanHistory.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
        
        await db.delete(scan)
        await db.commit()
        
        logger.info(f"Deleted scan record {scan_id}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete scan"
        )
