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

"""
New Scan API Schemas - Enhanced Structure
Pydantic models for detailed URL scanning responses
"""

from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List
from datetime import datetime


class ScanRequest(BaseModel):
    """Request model for URL scanning"""
    url: HttpUrl
    include_osint: bool = Field(default=True, description="Include OSINT data enrichment")
    deep_analysis: bool = Field(default=False, description="Perform deep analysis (slower)")
    language: Optional[str] = Field(default="en", description="Language code for response (en/vi)")


# New Detailed Response Structure
class VerdictData(BaseModel):
    """Verdict information"""
    score: int = Field(..., ge=0, le=100, description="Risk score (0-100)")
    level: str = Field(..., description="Risk level: LOW, MEDIUM, HIGH, CRITICAL")
    target_brand: Optional[str] = Field(None, description="Impersonated brand if detected")
    threat_type: Optional[str] = Field(None, description="Type of threat detected")
    risk_factors: List[str] = Field(default_factory=list, description="List of detected high-risk factors")
    ai_conclusion: Optional[str] = Field(None, description="AI-generated narrative conclusion")


class NetworkData(BaseModel):
    """Network and domain information"""
    domain_age: Optional[str] = Field(None, description="Human-readable domain age")
    registrar: Optional[str] = Field(None, description="Domain registrar")
    isp: Optional[str] = Field(None, description="Internet Service Provider")
    country: Optional[str] = Field(None, description="Hosting country")
    ip: Optional[str] = Field(None, description="Primary IP address")


class ForensicsData(BaseModel):
    """Forensic analysis data"""
    typosquatting: bool = Field(False, description="Typosquatting detected")
    redirect_chain: Optional[List[str]] = Field(None, description="Redirect chain if detected")
    obfuscation: Optional[str] = Field(None, description="Obfuscation technique detected")


class ContentData(BaseModel):
    """Content analysis data"""
    has_login_form: Optional[bool] = Field(None, description="Login form detected")
    screenshot_url: Optional[str] = Field(None, description="Screenshot URL")
    external_resources: Optional[List[str]] = Field(None, description="External resource domains")


class AdvancedData(BaseModel):
    """Advanced detection features"""
    telegram_bot_detected: bool = Field(False, description="Telegram bot API detected")
    discord_webhook_detected: Optional[bool] = Field(None, description="Discord webhook detected")
    ssl_issuer: Optional[str] = Field(None, description="SSL certificate issuer")
    ssl_validity: Optional[str] = Field(None, description="SSL validity period")


class IntelligenceData(BaseModel):
    """Threat intelligence data"""
    virustotal_score: Optional[str] = Field(None, description="VirusTotal detection ratio")
    google_safebrowsing: Optional[str] = Field(None, description="Google Safe Browsing status")


class GodModeAnalysis(BaseModel):
    """God Mode AI Analysis result - Elite threat detection"""
    verdict: str = Field(..., description="AI verdict: SAFE, SUSPICIOUS, or PHISHING")
    risk_score: int = Field(..., ge=0, le=100, description="AI-calculated risk score (0-100)")
    summary: str = Field(..., description="Short explanation of the verdict")
    impersonation_target: Optional[str] = Field(None, description="Detected brand impersonation target")
    risk_factors: List[str] = Field(default_factory=list, description="List of specific risk factors")
    technical_analysis: Optional[dict] = Field(None, description="Technical analysis details (url_integrity, domain_age)")
    recommendation: Optional[str] = Field(None, description="Actionable security advice")


class ScanResponse(BaseModel):
    """Complete scan response with new structure"""
    id: int = Field(..., description="Scan record ID")
    url: str = Field(..., description="Scanned URL")
    scanned_at: datetime = Field(..., description="Scan timestamp")
    
    verdict: VerdictData
    network: NetworkData
    forensics: ForensicsData
    content: ContentData
    advanced: AdvancedData
    intelligence: IntelligenceData
    
    # New fields for advanced frontend visualization
    technical_details: Optional[dict] = Field(None, description="Raw technical metrics (SSL age, entropy)")
    rag_matches: Optional[List[dict]] = Field(None, description="Detailed RAG threat matches")
    god_mode_analysis: Optional[GodModeAnalysis] = Field(None, description="God Mode AI Analysis result")
    vision_analysis: Optional[dict] = Field(None, description="Vision Scanner result (evasion detection, external connections)")
    
    # SOC Platform Features
    threat_graph: Optional[dict] = Field(None, description="React Flow compatible threat graph (nodes, edges)")
    yara_analysis: Optional[dict] = Field(None, description="YARA rule matches (crypto wallets, phishing kits, obfuscation)")
    abuse_report: Optional[dict] = Field(None, description="Auto-generated takedown report (recipient, subject, body)")
    phishing_kit: Optional[dict] = Field(None, description="Phishing kit fingerprint (detected, kit_name, confidence, matched_signatures)")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "id": 1,
                "url": "https://fake-facebook-login.com",
                "scanned_at": "2026-02-01T12:00:00Z",
                "verdict": {
                    "score": 85,
                    "level": "HIGH",
                    "target_brand": "Facebook",
                    "threat_type": "Credential Harvesting"
                },
                "network": {
                    "domain_age": "2 days",
                    "registrar": "NameCheap, Inc.",
                    "isp": "DigitalOcean",
                    "country": "Vietnam",
                    "ip": "1.2.3.4"
                },
                "forensics": {
                    "typosquatting": True,
                    "redirect_chain": ["http://bit.ly/xyz", "http://fake-fb.com"],
                    "obfuscation": "IP Usage detected"
                },
                "content": {
                    "has_login_form": True,
                    "screenshot_url": "/static/screenshots/uuid.jpg",
                    "external_resources": ["cdn.evil.com", "jquery.com"]
                },
                "advanced": {
                    "telegram_bot_detected": True,
                    "ssl_issuer": "Let's Encrypt (DV)",
                    "ssl_validity": "90 days"
                },
                "intelligence": {
                    "virustotal_score": "5/80",
                    "google_safebrowsing": "Malware"
                }
            }
        }
    }


class ScanHistoryResponse(BaseModel):
    """Schema for scan history list"""
    total: int
    scans: List[ScanResponse]
