"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

Admin router: stats, rate-limit simulation.
"""

import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database import get_db
from app.models import ScanLog, User
from app.routers.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/stats")
async def admin_stats(
    response: Response,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Analytics: total scans, phishing vs safe, scans per day (last 7 days).
    Rate limit simulation: if role is 'user' and scans_today > 5, add warning header (no block).
    """
    if user.role != "admin":
        response.headers["X-RateLimit-Warning"] = "Admin only; limited data for non-admin."
    # Total scans
    total_result = await db.execute(select(func.count(ScanLog.id)))
    total_scans = total_result.scalar() or 0
    # Phishing vs safe
    phishing_result = await db.execute(
        select(func.count(ScanLog.id)).where(func.lower(ScanLog.verdict).in_(["phishing", "high", "critical"]))
    )
    phishing_count = phishing_result.scalar() or 0
    safe_count = total_scans - phishing_count
    # Scans per day (last 7 days)
    since = datetime.utcnow() - timedelta(days=7)
    per_day_result = await db.execute(
        select(func.date(ScanLog.timestamp).label("day"), func.count(ScanLog.id).label("count"))
        .where(ScanLog.timestamp >= since)
        .group_by(func.date(ScanLog.timestamp))
        .order_by(func.date(ScanLog.timestamp))
    )
    rows = per_day_result.all()
    scans_per_day = [{"date": str(r.day), "count": r.count} for r in rows]
    # Rate limit simulation: scans today for this user
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    user_scans_result = await db.execute(
        select(func.count(ScanLog.id)).where(
            ScanLog.user_id == user.id, ScanLog.timestamp >= today_start
        )
    )
    scans_today = user_scans_result.scalar() or 0
    if user.role == "user" and scans_today > 5:
        response.headers["X-RateLimit-Warning"] = "Demo: more than 5 scans today; consider upgrading."
    # Active users (distinct user_id in ScanLog, plus null = guest)
    active_result = await db.execute(select(func.count(func.distinct(ScanLog.user_id))))
    active_users = active_result.scalar() or 0
    return {
        "total_scans": total_scans,
        "phishing_detected": phishing_count,
        "safe_count": safe_count,
        "scans_per_day": scans_per_day,
        "active_users": active_users,
    }
