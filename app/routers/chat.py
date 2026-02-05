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
Chat Router - AI Chatbot Endpoints
Handles Gemini AI chatbot interactions (Legacy + Sentinel AI)
"""

import logging
from fastapi import APIRouter, HTTPException
from app.schemas.chat import ChatRequest, ChatResponse, SentinelChatRequest, SentinelChatResponse
from app.services.chatbot import get_chatbot_response, is_chatbot_available
from app.services.chat_agent import ask_sentinel, is_sentinel_available

logger = logging.getLogger(__name__)

# Create chat router
router = APIRouter()


@router.post("/", response_model=ChatResponse)
async def chat_with_ai(chat_request: ChatRequest):
    """
    Chat with AI assistant about phishing scan results
    
    Send a message to the AI chatbot to get explanations about scan results.
    Optionally include scan context for more specific answers.
    
    **Example without scan context:**
    ```json
    {
        "message": "What is phishing?"
    }
    ```
    
    **Example with scan context:**
    ```json
    {
        "message": "Why is this link dangerous?",
        "scan_context": {
            "url": "https://suspicious-site.com",
            "is_phishing": true,
            "confidence_score": 95.5,
            "threat_type": "Credential Harvesting",
            "osint": {
                "domain_age_days": 5,
                "server_location": "Unknown",
                "has_mail_server": false
            }
        }
    }
    ```
    
    **Returns:**
    - AI-generated response explaining the scan results
    - Security recommendations
    - Risk assessment
    """
    try:
        logger.info(f"Chat request received: {chat_request.message[:100]}")
        
        # Check if chatbot is available
        if not is_chatbot_available():
            logger.warning("Chatbot service not available - GEMINI_API_KEY not configured")
            return ChatResponse(
                success=False,
                message=chat_request.message,
                response=None,
                error="Chatbot service is not available. Please configure GEMINI_API_KEY environment variable."
            )
        
        # Get AI response
        result = get_chatbot_response(
            message=chat_request.message,
            scan_context=chat_request.scan_context
        )
        
        # Return formatted response
        return ChatResponse(
            success=result['success'],
            message=chat_request.message,
            response=result.get('response'),
            error=result.get('error')
        )
        
    except Exception as e:
        logger.error(f"Error in chat endpoint: {e}", exc_info=True)
        return ChatResponse(
            success=False,
            message=chat_request.message,
            response=None,
            error=f"Internal server error: {str(e)}"
        )


@router.post("/sentinel", response_model=SentinelChatResponse)
async def chat_with_sentinel(request: SentinelChatRequest):
    """
    Chat with Sentinel AI - Advanced Cyber Security Expert
    
    Sentinel AI provides professional security analysis with stern warnings for phishing.
    
    **Request Format:**
    ```json
    {
        "message": "Is this safe?",
        "scan_result_id": "optional_id",
        "context_data": {
            "url": "https://paypal-verify.tk",
            "verdict": "PHISHING",
            "confidence_score": 98.5,
            "threat_type": "credential_theft"
        }
    }
    ```
    
    **Response Format:**
    ```json
    {
        "reply": "⚠️ CRITICAL WARNING: This URL is highly dangerous...",
        "scanned_url": "https://paypal-verify.tk"
    }
    ```
    
    **Features:**
    - Professional cyber security analysis
    - Stern warnings for phishing threats
    - Actionable security advice
    - Brief and professional responses
    - **AUTO-SCAN**: Detects URLs in message and automatically scans them
    """
    try:
        logger.info(f"[Sentinel AI] Request: {request.message[:100]}")
        logger.info(f"[Sentinel AI] Language: {request.language}")
        logger.debug(f"[Sentinel AI] Full request details - scan_result_id: {request.scan_result_id}, has_context: {request.context_data is not None}")
        
        # Check if Sentinel AI is available
        if not is_sentinel_available():
            logger.warning("Sentinel AI not available - GEMINI_API_KEY not configured")
            raise HTTPException(
                status_code=503,
                detail="Sentinel AI service is not available. Please configure GEMINI_API_KEY environment variable."
            )
        
        # Prepare scan context from context_data
        scan_context = None
        if request.context_data:
            scan_context = {
                'url': request.context_data.get('url', 'Unknown URL'),
                'verdict': request.context_data.get('verdict', 'UNKNOWN'),
                'confidence_score': request.context_data.get('confidence_score', 0.0),
                'is_phishing': request.context_data.get('verdict', '').upper() == 'PHISHING',
                'threat_type': request.context_data.get('threat_type'),
                'osint': request.context_data.get('osint', {}),
                'forensics': request.context_data.get('forensics', {})
            }
            
            # Log scan result ID if provided
            if request.scan_result_id:
                logger.info(f"[Sentinel AI] Scan Result ID: {request.scan_result_id}")
        
        # Ask Sentinel AI (language support can be added to ask_sentinel later)
        result = ask_sentinel(
            user_message=request.message,
            scan_context=scan_context
        )
        
        # Handle errors
        if not result['success']:
            error_msg = result.get('error', 'Unknown error occurred')
            logger.error(f"[Sentinel AI] Error: {error_msg}")
            raise HTTPException(
                status_code=500,
                detail=error_msg
            )
        
        # Return response with scanned URL (if auto-detected)
        reply_text = result['reply']
        scanned_url = result.get('scanned_url')
        
        if scanned_url:
            logger.info(f"[Sentinel AI] Auto-scanned URL: {scanned_url}")
        logger.info(f"[Sentinel AI] Response generated ({len(reply_text)} chars)")
        
        return SentinelChatResponse(reply=reply_text, scanned_url=scanned_url)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Sentinel AI] Unexpected error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )
