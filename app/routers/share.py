"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

Share: GET /share/{scan_id} returns full result from ScanLog.
"""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import ScanLog

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Share"])


@router.get("/share/{scan_id}")
async def get_share_result(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Fetch full scan result from DB for share link. Returns stored JSON."""
    result = await db.execute(select(ScanLog).where(ScanLog.id == scan_id))
    scan_log = result.scalar_one_or_none()
    if not scan_log or not scan_log.full_result_json:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found or not shareable")
    try:
        data = json.loads(scan_log.full_result_json)
    except Exception as e:
        logger.warning(f"Invalid JSON in ScanLog {scan_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Invalid scan data")
    return JSONResponse(content=data)
