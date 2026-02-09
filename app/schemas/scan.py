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

"""Scan schemas for request/response validation"""

from datetime import datetime
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any
from urllib.parse import urlparse


class ScanRequest(BaseModel):
    """Schema for URL scan request"""
    url: str = Field(..., description="URL to scan for phishing")
    include_osint: bool = Field(default=True, description="Include OSINT data in response")
    language: str = Field(default="en", description="Language for AI analysis and report (en/vi)")
    
    @field_validator('url')
    @classmethod
    def sanitize_url(cls, v: str) -> str:
        """
        Sanitize and validate URL input.
        Auto-prepends https:// if no protocol is specified.
        
        Args:
            v: Raw URL string from request
            
        Returns:
            Sanitized URL with protocol
            
        Raises:
            ValueError: If URL is invalid
        """
        if not v or not v.strip():
            raise ValueError("URL cannot be empty")
        
        url = v.strip()
        
        # Fix common protocol typos
        if url.lower().startswith('htps://'):
            url = 'https://' + url[7:]
        elif url.lower().startswith('htp://'):
            url = 'http://' + url[6:]
        elif url.lower().startswith('ttp://'):
            url = 'http://' + url[6:]
        
        # Add https:// if no protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate URL format
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")
            
            # Check if hostname is valid
            hostname = parsed.netloc.lower()
            if not hostname or hostname == 'localhost':
                # localhost is valid
                pass
            elif '.' not in hostname and not hostname.replace('.', '').replace(':', '').isdigit():
                # Must have a dot (domain) or be an IP address
                raise ValueError("Invalid hostname: must be a domain or IP address")
                
            return url
        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")



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
