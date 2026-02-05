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

"""Scan history model"""

from datetime import datetime
from sqlalchemy import String, Boolean, Numeric, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional, TYPE_CHECKING

from app.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class ScanHistory(Base):
    """Scan history model to store phishing detection results"""
    
    __tablename__ = "scan_history"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    is_phishing: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    confidence_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    threat_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Relationship to user
    user: Mapped[Optional["User"]] = relationship("User", back_populates="scans")
    
    def __repr__(self) -> str:
        return f"<ScanHistory(id={self.id}, url='{self.url[:50]}...', is_phishing={self.is_phishing})>"
