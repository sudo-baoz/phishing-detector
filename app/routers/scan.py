"""URL Scanning Router - Phishing Detection"""

import logging
from datetime import datetime
from typing import Optional
import re
from urllib.parse import urlparse

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.models import ScanHistory
from app.schemas.scan import ScanRequest, ScanResponse, ScanHistoryResponse

logger = logging.getLogger(__name__)

router = APIRouter()


def extract_features(url: str) -> dict:
    """Extract features from URL for ML model"""
    try:
        parsed = urlparse(url)
    except:
        parsed = None
    
    # Extract all features (must match training features)
    features = {
        'url_length': len(url),
        'dot_count': url.count('.'),
        'has_at_symbol': 1 if '@' in url else 0,
        'is_https': 1 if url.startswith('https://') else 0,
        'digit_count': sum(c.isdigit() for c in url),
        'hyphen_count': url.count('-'),
        'underscore_count': url.count('_'),
        'slash_count': url.count('/'),
        'question_count': url.count('?'),
        'ampersand_count': url.count('&'),
        'domain_length': len(parsed.netloc) if parsed else 0,
        'has_suspicious_tld': 1 if any(url.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq']) else 0,
    }
    
    return features


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
    request: Request,
    scan_request: ScanRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Scan a URL for phishing detection
    
    - **url**: URL to scan (must be valid HTTP/HTTPS URL)
    
    Returns prediction with confidence score and threat type
    """
    
    logger.info(f"Scanning URL: {scan_request.url}")
    
    try:
        # Get ML model from app state
        ml_model = request.app.state.get_ml_model()
        ml_scaler = request.app.state.get_ml_scaler()
        ml_feature_names = request.app.state.get_ml_feature_names()
        
        # Extract features
        features = extract_features(str(scan_request.url))
        
        # Create DataFrame with features in correct order
        X = pd.DataFrame([features])[ml_feature_names]
        
        # Scale features
        X_scaled = ml_scaler.transform(X)
        
        # Make prediction
        prediction = ml_model.predict(X_scaled)[0]
        
        # Get prediction probability
        try:
            prediction_proba = ml_model.predict_proba(X_scaled)[0]
            confidence_score = float(prediction_proba[prediction] * 100)
        except:
            confidence_score = 85.0 if prediction == 1 else 90.0
        
        is_phishing = bool(prediction == 1)
        
        # Determine threat type
        threat_type = determine_threat_type(is_phishing, confidence_score, str(scan_request.url))
        
        logger.info(f"Prediction: {'PHISHING' if is_phishing else 'SAFE'} (Confidence: {confidence_score:.2f}%)")
        
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
            user_id=scan_record.user_id
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
