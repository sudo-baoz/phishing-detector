"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

SaaS: ScanLog stores full result JSON for share and analytics.
"""

from datetime import datetime
from sqlalchemy import String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional, TYPE_CHECKING

from app.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class ScanLog(Base):
    """Scan log for SaaS: full result JSON for share link and stats."""

    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    verdict: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. SAFE, PHISHING
    score: Mapped[float] = mapped_column(Float, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    full_result_json: Mapped[str] = mapped_column(Text, nullable=True)

    user: Mapped[Optional["User"]] = relationship("User", back_populates="scan_logs")

    def __repr__(self) -> str:
        return f"<ScanLog(id={self.id}, url='{self.url[:50]}...', verdict={self.verdict})>"
