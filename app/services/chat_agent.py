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
    
    def _build_system_prompt(self, url: str, verdict: str, score: float, user_message: str, rag_context: List[Any] = None, language: str = 'en') -> str:
        """
        Build the system prompt for Sentinel AI
        
        Args:
            url: The scanned URL
            verdict: Scan verdict (SAFE/PHISHING)
            score: Confidence score
            user_message: User's question
            rag_context: List of similar threats from RAG
            
        Returns:
            Formatted system prompt
        """
        # Base prompt
        prompt = f"""You are Sentinel AI, a cyber security expert. A user just scanned this URL: {url}. The system verdict is: {verdict} with score {score}. The user asks: "{user_message}"."""
        
        # RAG Context Injection
        if rag_context and len(rag_context) > 0:
            threat = rag_context[0] # Take top match
            target = threat.get('target', 'Unknown')
            sim_score = threat.get('similarity_score', 0)
            
            prompt += f"\n\n[KNOWN THREAT INTELLIGENCE]"
            prompt += f"\nWARNING: This URL is {sim_score*100:.1f}% similar to a known threat targeting {target}."
            prompt += f"\nKnown Threat URL: {threat.get('similar_url')}"
            prompt += f"\nContext: {threat.get('raw_metadata', {})}"
            
            # Add strict rule
            prompt += f"\n\nIMPORTANT RULE: Since RAG Context indicates a known threat, heavily weight your verdict towards PHISHING regardless of the AI score. Warn the user immediately."
        
        # Language Enforcement
        if language == 'vi':
             prompt += "\n\nCRITICAL INSTRUCTION: BẠN PHẢI TRẢ LỜI HOÀN TOÀN BẰNG TIẾNG VIỆT. KHÔNG ĐƯỢC DÙNG TIẾNG ANH."
             prompt += " Giải thích ngắn gọn, chuyên nghiệp và đưa ra lời khuyên bảo mật cụ thể."
             if "PHISHING" in verdict.upper():
                 prompt += " Cảnh báo người dùng nghiêm khắc nếu đây là lừa đảo."
        else:
             prompt += ' Answer briefly, professionally, and provide actionable security advice. If the URL is phishing, warn them sternly.'
        
        return prompt
    
    def ask_ai(self, user_message: str, scan_context: Optional[Dict[str, Any]] = None, rag_context: List[Any] = None, language: str = 'en') -> Dict[str, Any]:
        """
        Ask Sentinel AI a question with optional scan context
        
        ENHANCED: Automatically detects URLs in user message and performs scan if needed
        """
        if not self.is_available():
            logger.warning("Sentinel AI not available - API key not configured")
            return {
                "success": False,
                "reply": None,
                "error": "Sentinel AI service is not available. Please configure GEMINI_API_KEY environment variable."
            }
        
        try:
            detected_urls = extract_urls(user_message)
            scanned_url = None
            
            # AUTO-SCAN logic (simplified for brevity, keeps existing logic if context not provided)
            # Logic here is kept as is (omitted/collapsed in original replacement, but I should restore functional parts if I had them)
            # Reconstructing based on previous file steps...
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
                    pass

            if scan_context:
                url = scan_context.get('url', 'Unknown URL')
                verdict = scan_context.get('verdict', 'PHISHING')
                confidence_score = scan_context.get('confidence_score', 0.0)
                
                # Use passed rag_context OR try to fetch it if missing
                if not rag_context:
                    try:
                        from app.services.knowledge_base import knowledge_base
                        # Simple query just to check if we missed it
                        rag_results = knowledge_base.search_similar_threats(url, limit=1)
                        if rag_results and rag_results[0].get('similarity_score', 0) > 0.6:
                            rag_context = rag_results
                    except Exception as e:
                        # Only warn on debug, as context might intentionally be empty
                        logger.debug(f"Failed to auto-fetch RAG context: {e}")

                prompt = self._build_system_prompt(url, verdict, confidence_score, user_message, rag_context, language)
                
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
                prompt = f"""You are Sentinel AI, a cyber security expert. The user asks: "{user_message}"."""
                
                if language == 'vi':
                    prompt += "\n\nCRITICAL INSTRUCTION: BẠN PHẢI TRẢ LỜI HOÀN TOÀN BẰNG TIẾNG VIỆT."
                else:
                    prompt += " Answer briefly, professionally, and provide actionable security advice."
                
                # Try RAG for general questions too (Knowledge Base Q&A)
                if not rag_context:
                    try:
                        from app.services.knowledge_base import knowledge_base
                        similar_threats = knowledge_base.search_similar_threats(query_text=user_message, n_results=1)
                        if similar_threats and similar_threats[0]['similarity_score'] > 0.6:
                             rag_context = similar_threats
                    except Exception:
                        pass
                
                if rag_context and len(rag_context) > 0:
                     threat = rag_context[0]
                     prompt += f"\n\nContext: The user might be asking about this known threat:"
                     prompt += f"\nURL: {threat.get('similar_url')}"
                     prompt += f"\nTarget: {threat.get('target')}"
            
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


def ask_sentinel(user_message: str, scan_context: Optional[Dict[str, Any]] = None, rag_context: List[Any] = None, language: str = 'en') -> Dict[str, Any]:
    """
    Convenience function to ask Sentinel AI
    
    Args:
        user_message: User's question
        scan_context: Optional scan result context
        rag_context: Optional RAG context list
    
    Returns:
        Dictionary with success, reply, and optional error
    """
    return sentinel_ai.ask_ai(user_message, scan_context, rag_context, language)


def is_sentinel_available() -> bool:
    """Check if Sentinel AI service is available"""
    return sentinel_ai.is_available()
