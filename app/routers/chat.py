"""
Chat Router - AI Chatbot Endpoints
Handles Gemini AI chatbot interactions
"""

import logging
from fastapi import APIRouter, HTTPException
from app.schemas.chat import ChatRequest, ChatResponse
from app.services.chatbot import get_chatbot_response, is_chatbot_available

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
