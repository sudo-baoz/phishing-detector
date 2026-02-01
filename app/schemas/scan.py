"""Scan schemas for request/response validation"""

from datetime import datetime
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional


class ScanRequest(BaseModel):
    """Schema for URL scan request"""
    url: HttpUrl = Field(..., description="URL to scan for phishing")


class ScanResponse(BaseModel):
    """Schema for scan result response"""
    id: int
    url: str
    is_phishing: bool
    confidence_score: float = Field(..., ge=0.0, le=100.0)
    threat_type: Optional[str] = None
    scanned_at: datetime
    user_id: Optional[int] = None
    
    model_config = {"from_attributes": True}


class ScanHistoryResponse(BaseModel):
    """Schema for scan history list"""
    total: int
    scans: list[ScanResponse]
