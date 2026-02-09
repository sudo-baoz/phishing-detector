"""
Phishing Detector - Forensic PDF Report Download
Copyright (c) 2026 BaoZ

GET /report/{scan_id}/download returns a PDF forensic report.
"""

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import ScanHistory
from app.services.report_generator import generate_pdf

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_CACHE_SIZE = 100


def _build_scan_data_from_db(record: ScanHistory) -> Dict[str, Any]:
    """Build minimal scan_data for PDF from DB record (no screenshots/network)."""
    return {
        "id": record.id,
        "url": record.url,
        "scanned_at": record.scanned_at,
        "is_phishing": record.is_phishing,
        "confidence_score": float(record.confidence_score),
        "verdict": {"score": float(record.confidence_score), "level": "HIGH" if record.is_phishing else "LOW"},
        "network": {"ip": None, "country": None, "domain_age": None, "registrar": None},
        "technical_details": {},
    }


@router.get("/{scan_id}/download")
async def download_forensic_report(
    scan_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Download Forensic Analysis Report as PDF.
    Uses cached full scan result when available; otherwise builds from DB (no screenshots).
    """
    cache = getattr(request.app.state, "scan_result_cache", None)
    if cache is None:
        request.app.state.scan_result_cache = {}
        cache = request.app.state.scan_result_cache

    scan_data = cache.get(scan_id)
    if not scan_data:
        result = await db.execute(select(ScanHistory).where(ScanHistory.id == scan_id))
        record = result.scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        scan_data = _build_scan_data_from_db(record)

    buf = generate_pdf(scan_data)
    pdf_bytes = buf.read()
    filename = f"forensic-report-{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
