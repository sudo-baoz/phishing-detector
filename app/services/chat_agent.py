"""
Sentinel AI - Advanced Chat Agent Service
AI-powered cyber security assistant using Google Gemini API
"""

import os
import re
import logging
from typing import Dict, Any, Optional, List
import google.generativeai as genai
from app.config import settings

logger = logging.getLogger(__name__)


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from user message using regex
    
    Args:
        text: User message text
        
    Returns:
        List of detected URLs
    """
    # URL regex pattern (http/https, github, common domains)
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text)
    return urls


class SentinelAI:
    """
    Sentinel AI - Cyber Security Expert Chat Agent
    Provides professional security analysis and actionable advice
    """
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            cls._instance = super(SentinelAI, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize Gemini model with API key from environment"""
        if not self._initialized:
            self.model = None
            self._available = False
            
            try:
                # Get API key from settings (loads from .env)
                api_key = settings.GEMINI_API_KEY
                
                if not api_key or api_key.strip() == "":
                    logger.warning("GEMINI_API_KEY not set. Sentinel AI will not be available.")
                    self._initialized = True
                    return
                
                # Configure Gemini API
                genai.configure(api_key=api_key)
                
                # Initialize gemini-2.5-flash model (stable release June 17th, 2025)
                self.model = genai.GenerativeModel('gemini-2.5-flash')
                self._available = True
                
                logger.info("[OK] Sentinel AI initialized successfully with gemini-2.5-flash")
                
            except Exception as e:
                logger.error(f"Failed to initialize Sentinel AI: {e}")
                self.model = None
                self._available = False
            
            self._initialized = True
    
    def is_available(self) -> bool:
        """Check if Sentinel AI is available"""
        return self._available and self.model is not None
    
    def _build_system_prompt(self, url: str, verdict: str, score: float, user_message: str) -> str:
        """
        Build the system prompt for Sentinel AI
        
        Args:
            url: The scanned URL
            verdict: Scan verdict (SAFE/PHISHING)
            score: Confidence score
            user_message: User's question
            
        Returns:
            Formatted system prompt
        """
        prompt = f"""You are Sentinel AI, a cyber security expert. A user just scanned this URL: {url}. The system verdict is: {verdict} with score {score}. The user asks: "{user_message}". Answer briefly, professionally, and provide actionable security advice. If the URL is phishing, warn them sternly."""
        
        return prompt
    
    def ask_ai(self, user_message: str, scan_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Ask Sentinel AI a question with optional scan context
        
        ENHANCED: Automatically detects URLs in user message and performs scan if needed
        
        Args:
            user_message: User's question
            scan_context: Optional scan result context containing:
                - url: Scanned URL
                - verdict: Scan verdict (SAFE/PHISHING/SUSPICIOUS)
                - confidence_score: Prediction confidence
                - threat_type: Type of threat detected
                - ... other scan details
        
        Returns:
            Dictionary with:
                - success: bool
                - reply: AI response text
                - error: Optional error message
                - scanned_url: URL that was scanned (if auto-detected)
        
        Example:
            >>> agent = SentinelAI()
            >>> result = agent.ask_ai("Check https://example.com")
            # Auto-scans the URL and returns analysis
        """
        if not self.is_available():
            logger.warning("Sentinel AI not available - API key not configured")
            return {
                "success": False,
                "reply": None,
                "error": "Sentinel AI service is not available. Please configure GEMINI_API_KEY environment variable."
            }
        
        try:
            # AUTO-SCAN: Detect URLs in user message
            detected_urls = extract_urls(user_message)
            scanned_url = None
            
            if detected_urls and not scan_context:
                # User mentioned a URL but no scan context provided - auto-scan it!
                target_url = detected_urls[0]  # Use first URL found
                scanned_url = target_url
                
                logger.info(f"[AUTO-SCAN] Detected URL in message: {target_url}")
                logger.info("[AUTO-SCAN] Triggering automatic scan...")
                
                try:
                    # Import scan services
                    from app.services.ai_engine import phishing_predictor
                    from app.services.osint import collect_osint_data, get_osint_summary
                    
                    # Perform phishing prediction
                    prediction_result = phishing_predictor.predict(target_url)
                    is_phishing = prediction_result['is_phishing']
                    confidence_score = prediction_result['confidence_score']
                    
                    # Determine threat type
                    url_lower = target_url.lower()
                    if is_phishing:
                        if any(kw in url_lower for kw in ['login', 'signin', 'account', 'verify']):
                            threat_type = "credential_theft"
                        elif any(kw in url_lower for kw in ['download', 'exe', 'apk']):
                            threat_type = "malware"
                        elif any(kw in url_lower for kw in ['prize', 'win', 'claim']):
                            threat_type = "scam"
                        elif any(kw in url_lower for kw in ['bank', 'paypal', 'payment']):
                            threat_type = "financial_fraud"
                        else:
                            threat_type = "phishing"
                    else:
                        threat_type = None
                    
                    # Collect OSINT data
                    osint_dict = None
                    try:
                        osint_full = collect_osint_data(target_url)
                        osint_dict = get_osint_summary(osint_full)
                        logger.info(f"[OK] OSINT collected: {osint_dict.get('server_location')}")
                    except Exception as e:
                        logger.warning(f"OSINT collection failed: {e}")
                    
                    # Build scan context
                    scan_context = {
                        'url': target_url,
                        'verdict': 'PHISHING' if is_phishing else 'SAFE',
                        'confidence_score': confidence_score,
                        'is_phishing': is_phishing,
                        'threat_type': threat_type,
                        'osint': osint_dict or {},
                        'forensics': {}
                    }
                    
                    logger.info(f"[OK] Auto-scan complete: {scan_context['verdict']} ({confidence_score:.1f}%)")
                    
                except Exception as scan_error:
                    logger.error(f"Auto-scan failed: {scan_error}")
                    # Continue without scan context, AI will give general advice
                    pass
            # Extract scan context if provided
            if scan_context:
                url = scan_context.get('url', 'Unknown URL')
                
                # Determine verdict
                is_phishing = scan_context.get('is_phishing', False)
                verdict = scan_context.get('verdict', 'PHISHING' if is_phishing else 'SAFE')
                
                # Get confidence score
                confidence_score = scan_context.get('confidence_score', 0.0)
                
                # Build system prompt with context
                prompt = self._build_system_prompt(url, verdict, confidence_score, user_message)
                
                # Add additional context details if available
                threat_type = scan_context.get('threat_type')
                if threat_type:
                    prompt += f"\nThreat Type: {threat_type}"
                
                # Add OSINT data if available
                osint = scan_context.get('osint', {})
                if osint:
                    domain_age = osint.get('domain_age_days')
                    location = osint.get('server_location')
                    if domain_age is not None:
                        prompt += f"\nDomain Age: {domain_age} days"
                    if location:
                        prompt += f"\nServer Location: {location}"
                
                # Add forensic details if available
                forensics = scan_context.get('forensics', {})
                if forensics:
                    obfuscation = forensics.get('obfuscation_detected')
                    if obfuscation:
                        prompt += f"\nObfuscation Detected: {obfuscation}"
            
            else:
                # No context - general cyber security question
                prompt = f"""You are Sentinel AI, a cyber security expert. The user asks: "{user_message}". Answer briefly, professionally, and provide actionable security advice."""
            
            # Generate response from Gemini
            logger.info(f"Sending prompt to Gemini (length: {len(prompt)} chars)")
            response = self.model.generate_content(prompt)
            
            # Extract text from response
            reply_text = response.text
            
            logger.info(f"[OK] Sentinel AI response generated ({len(reply_text)} chars)")
            
            return {
                "success": True,
                "reply": reply_text,
                "error": None,
                "scanned_url": scanned_url  # Include URL that was auto-scanned (if any)
            }
        
        except Exception as e:
            logger.error(f"Error generating Sentinel AI response: {e}", exc_info=True)
            
            # Handle specific API errors
            error_msg = str(e)
            if "API_KEY" in error_msg.upper():
                error_msg = "Invalid or expired API key. Please check your GEMINI_API_KEY configuration."
            elif "QUOTA" in error_msg.upper() or "RATE" in error_msg.upper():
                error_msg = "API quota exceeded or rate limit reached. Please try again later."
            elif "BLOCKED" in error_msg.upper() or "SAFETY" in error_msg.upper():
                error_msg = "Content was blocked by safety filters. Please rephrase your question."
            else:
                error_msg = f"Failed to generate response: {error_msg}"
            
            return {
                "success": False,
                "reply": None,
                "error": error_msg
            }


# Global singleton instance
sentinel_ai = SentinelAI()


def ask_sentinel(user_message: str, scan_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to ask Sentinel AI
    
    Args:
        user_message: User's question
        scan_context: Optional scan result context
    
    Returns:
        Dictionary with success, reply, and optional error
    """
    return sentinel_ai.ask_ai(user_message, scan_context)


def is_sentinel_available() -> bool:
    """Check if Sentinel AI service is available"""
    return sentinel_ai.is_available()
