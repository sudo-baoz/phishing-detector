"""Scan schemas for request/response validation"""

from datetime import datetime
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Dict, Any


class ScanRequest(BaseModel):
    """Schema for URL scan request"""
    url: HttpUrl = Field(..., description="URL to scan for phishing")
    include_osint: bool = Field(default=True, description="Include OSINT data in response")


class OSINTData(BaseModel):
    """Schema for OSINT enrichment data"""
    domain: Optional[str] = None
    ip: Optional[str] = None
    server_location: Optional[str] = None
    isp: Optional[str] = None
    registrar: Optional[str] = None
    domain_age_days: Optional[int] = None
    has_mail_server: Optional[bool] = None


class ScanResponse(BaseModel):
    """Schema for scan result response"""
    id: int
    url: str
    is_phishing: bool
    confidence_score: float = Field(..., ge=0.0, le=100.0)
    threat_type: Optional[str] = None
    scanned_at: datetime
    user_id: Optional[int] = None
    osint: Optional[OSINTData] = None
    
    model_config = {"from_attributes": True}


class ScanHistoryResponse(BaseModel):
    """Schema for scan history list"""
    total: int
    scans: list[ScanResponse]
