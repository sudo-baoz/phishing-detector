"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

"""URL Scanning Router - Phishing Detection"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.models import ScanHistory
from app.schemas.scan_new import (
    ScanRequest, ScanResponse, ScanHistoryResponse,
    VerdictData, NetworkData, ForensicsData, 
    ContentData, AdvancedData, IntelligenceData
)
from app.services.ai_engine import phishing_predictor
from app.services.osint import collect_osint_data, get_osint_summary
from app.services.knowledge_base import knowledge_base
from app.services.response_builder import response_builder
from app.security.turnstile import verify_turnstile  # Cloudflare Turnstile

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
    request: Request,  # ✅ Added Request for manual token extraction
    db: AsyncSession = Depends(get_db)
    # ⚠️ Removed Depends(verify_turnstile) - now done manually for fail-fast
):
    """
    Scan a URL for phishing detection (Protected by Cloudflare Turnstile)
    
    - **url**: URL to scan (must be valid HTTP/HTTPS URL)
    - **include_osint**: Include OSINT data enrichment (default: True)
    - **cf-turnstile-response**: Cloudflare Turnstile token (required in header or body)
    
    Returns prediction with confidence score, threat type, and optional OSINT data
    
    **Flow:**
    1. VERIFY TURNSTILE TOKEN FIRST (Fail Fast - 1-2s)
    2. If valid, start heavy analysis (30s+)
    3. Return result
    """
    
    # ============================================================
    # STEP 1: VERIFY TURNSTILE TOKEN IMMEDIATELY (FAIL FAST!)
    # ============================================================
    # This MUST happen BEFORE any heavy processing to prevent token timeout
    logger.info(f"[1/4] Verifying Turnstile token for URL: {scan_request.url}")
    
    try:
        # Explicitly await token verification as FIRST step
        turnstile_verified = await verify_turnstile(request)
        logger.info(f"[OK] Turnstile verification successful: {turnstile_verified.get('success', False)}")
    except HTTPException as e:
        # Token verification failed - reject immediately (fail fast)
        logger.warning(f"[REJECTED] Turnstile verification failed - blocking request")
        raise  # Re-raise the 403 HTTPException from verify_turnstile
    
    # ============================================================
    # STEP 2: HEAVY ANALYSIS (Only if token is valid)
    # ============================================================
    logger.info(f"[2/4] Starting phishing analysis for: {scan_request.url}")
    
    try:
        url_str = str(scan_request.url)
        
        # [NEW] Semantic RAG Search using ChromaDB
        # Find similar known threats to provide context for the AI scanner
        similar_threats = knowledge_base.search_similar_threats(url_str)
        if similar_threats:
            logger.info(f"[RAG] Found {len(similar_threats)} similar threats in Knowledge Base")
        
        # Use PhishingPredictor service for prediction
        # Note: similar_threats context will be passed here in next update
        prediction_result = phishing_predictor.predict(url_str)
        
        is_phishing = prediction_result['is_phishing']
        confidence_score = prediction_result['confidence_score']
        
        # Determine threat type
        threat_type = determine_threat_type(is_phishing, confidence_score, url_str)
        
        logger.info(f"Prediction: {'PHISHING' if is_phishing else 'SAFE'} (Confidence: {confidence_score:.2f}%)")
        
        # ============================================================
        # STEP 3: OSINT DATA COLLECTION (Optional heavy operation)
        # ============================================================
        osint_dict = None
        if scan_request.include_osint:
            try:
                logger.info("[3/4] Collecting OSINT data...")
                osint_full = collect_osint_data(url_str)
                osint_dict = get_osint_summary(osint_full)
                logger.info(f"[OK] OSINT data collected: {osint_dict.get('server_location')}")
            except Exception as e:
                logger.warning(f"Failed to collect OSINT data: {e}")
        
        # ============================================================
        # STEP 4: SAVE TO DATABASE & BUILD RESPONSE
        # ============================================================
        logger.info("[4/4] Saving scan result to database...")
        
        # Save to database
        scan_record = ScanHistory(
            url=url_str,
            is_phishing=is_phishing,
            confidence_score=round(confidence_score, 2),
            threat_type=threat_type,
            scanned_at=datetime.utcnow(),
            user_id=None
        )
        
        db.add(scan_record)
        await db.commit()
        await db.refresh(scan_record)
        
        logger.info(f"Scan result saved to database (ID: {scan_record.id})")
        
        # Build complete response using ResponseBuilder with deep analysis
        response_data = response_builder.build_complete_response(
            scan_id=scan_record.id,
            url=url_str,
            scanned_at=scan_record.scanned_at,
            is_phishing=is_phishing,
            confidence_score=confidence_score,
            threat_type=threat_type,
            osint_data=osint_dict,
            deep_analysis=scan_request.deep_analysis
        )
        
        # Convert to Pydantic models
        return ScanResponse(
            id=response_data['id'],
            url=response_data['url'],
            scanned_at=response_data['scanned_at'],
            verdict=VerdictData(**response_data['verdict']),
            network=NetworkData(**response_data['network']),
            forensics=ForensicsData(**response_data['forensics']),
            content=ContentData(**response_data['content']),
            advanced=AdvancedData(**response_data['advanced']),
            intelligence=IntelligenceData(**response_data['intelligence'])
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
