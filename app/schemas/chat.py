"""
Chat API Schemas
Pydantic models for chatbot requests and responses
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


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
