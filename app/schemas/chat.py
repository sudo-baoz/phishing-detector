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
Chat API Schemas
Pydantic models for chatbot requests and responses
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class SentinelChatRequest(BaseModel):
    """
    Request model for Sentinel AI chat endpoint
    
    Example:
        {
            "message": "Is this safe?",
            "scan_result_id": "optional_id_123",
            "context_data": {
                "url": "https://example.com",
                "verdict": "PHISHING",
                "confidence_score": 95.5,
                "threat_type": "credential_theft"
            }
        }
    """
    message: str = Field(
        ..., 
        min_length=1, 
        max_length=1000,
        description="User's question to Sentinel AI"
    )
    scan_result_id: Optional[str] = Field(
        default=None,
        description="Optional ID of the scan result for reference"
    )
    context_data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="JSON object containing scan result data"
    )
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "message": "Is this safe?",
                    "scan_result_id": "scan_12345",
                    "context_data": {
                        "url": "https://paypal-login.tk/verify",
                        "verdict": "PHISHING",
                        "confidence_score": 98.7,
                        "threat_type": "credential_theft",
                        "forensics": {
                            "obfuscation_detected": "Suspicious TLD (.tk)"
                        }
                    }
                }
            ]
        }
    }


class SentinelChatResponse(BaseModel):
    """
    Response model for Sentinel AI chat endpoint
    
    Example:
        {
            "reply": "Based on the scan, this URL uses a homograph attack...",
            "scanned_url": "https://example.com"
        }
    """
    reply: str = Field(
        ...,
        description="Sentinel AI's response"
    )
    scanned_url: Optional[str] = Field(
        default=None,
        description="URL that was automatically scanned (if detected in user message)"
    )
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "reply": "⚠️ **CRITICAL WARNING** ⚠️\n\nThis URL is HIGHLY DANGEROUS. Based on the scan:\n\n**Threat Detected:** Credential Theft Attack\n**Confidence:** 98.7%\n\n**Why It's Phishing:**\n- Uses suspicious .tk domain (free, commonly abused)\n- Impersonates PayPal login page\n- Designed to steal your credentials\n\n**⛔ DO NOT:**\n- Click this link\n- Enter any passwords\n- Share this URL\n\n**✅ Recommended Actions:**\n1. Delete any emails containing this link\n2. Report it as phishing\n3. Go directly to paypal.com (type it manually)\n4. If you entered credentials, change your password IMMEDIATELY",
                    "scanned_url": "https://paypal-verify.tk"
                }
            ]
        }
    }


class ChatRequest(BaseModel):
    """
    Request model for chatbot endpoint
    
    Example:
        {
            "message": "Why is this link dangerous?",
            "scan_context": {
                "url": "https://example.com",
                "is_phishing": true,
                "confidence_score": 95.5,
                "threat_type": "Credential Harvesting",
                "osint": {...}
            }
        }
    """
    message: str = Field(
        ..., 
        min_length=1, 
        max_length=1000,
        description="User's question about the scan results"
    )
    scan_context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional scan results context to help AI answer the question"
    )
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "message": "Why is this link dangerous?",
                    "scan_context": {
                        "url": "https://suspicious-site.com",
                        "is_phishing": True,
                        "confidence_score": 95.5,
                        "threat_type": "Credential Harvesting",
                        "osint": {
                            "domain": "suspicious-site.com",
                            "domain_age_days": 5,
                            "server_location": "Unknown",
                            "has_mail_server": False
                        }
                    }
                },
                {
                    "message": "What is phishing?",
                    "scan_context": None
                }
            ]
        }
    }


class ChatResponse(BaseModel):
    """
    Response model for chatbot endpoint
    
    Example:
        {
            "success": true,
            "message": "User's original question",
            "response": "AI's detailed answer...",
            "error": null
        }
    """
    success: bool = Field(
        ...,
        description="Whether the chatbot successfully generated a response"
    )
    message: str = Field(
        ...,
        description="Original user message (for context)"
    )
    response: Optional[str] = Field(
        default=None,
        description="AI-generated response text"
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if request failed"
    )
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "success": True,
                    "message": "Why is this link dangerous?",
                    "response": "This link is flagged as dangerous because:\n\n1. **Brand New Domain**: Created only 5 days ago\n2. **No Email Server**: Legitimate sites usually have email capability\n3. **High AI Confidence**: 95.5% certainty it's phishing\n\nℹ️ **Recommendation**: Do NOT click this link or enter any personal information.",
                    "error": None
                },
                {
                    "success": False,
                    "message": "Test question",
                    "response": None,
                    "error": "Chatbot service is not available. Please configure GEMINI_API_KEY."
                }
            ]
        }
    }
