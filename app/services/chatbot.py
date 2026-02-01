"""
Gemini AI Chatbot Service
Integrates Google Gemini API for intelligent chatbot responses about scan results
"""

import logging
import google.generativeai as genai
from typing import Dict, Any, Optional
from app.config import settings

logger = logging.getLogger(__name__)


class GeminiChatbot:
    """
    Singleton class for Gemini AI chatbot integration
    Provides intelligent responses about phishing scan results
    """
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GeminiChatbot, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize Gemini API with API key from environment"""
        if not self._initialized:
            try:
                if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "":
                    logger.warning("GEMINI_API_KEY not configured. Chatbot will not be available.")
                    self.model = None
                    self._available = False
                else:
                    genai.configure(api_key=settings.GEMINI_API_KEY)
                    # Use Gemini 2.5 Flash - stable and fast
                    self.model = genai.GenerativeModel('gemini-2.5-flash')
                    self._available = True
                    logger.info("Gemini AI chatbot initialized successfully")
                
                self._initialized = True
                
            except Exception as e:
                logger.error(f"Failed to initialize Gemini chatbot: {e}")
                self.model = None
                self._available = False
                self._initialized = True
    
    @property
    def is_available(self) -> bool:
        """Check if chatbot is available"""
        return self._available and self.model is not None
    
    def construct_prompt(
        self, 
        user_message: str, 
        scan_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Construct a detailed prompt for Gemini based on scan context
        
        Args:
            user_message: User's question about the scan
            scan_context: Dictionary containing scan results (optional)
        
        Returns:
            Formatted prompt string for Gemini
        """
        # Base system prompt
        base_prompt = """You are a Cyber Security Expert specializing in phishing detection and threat analysis. 
Your role is to explain security scan results in a clear, concise, and user-friendly manner.

GUIDELINES:
- Be professional yet approachable
- Explain technical terms in simple language
- Provide actionable security advice
- Keep responses under 150 words unless complex explanation needed
- Use bullet points for multiple points
- Emphasize critical threats clearly
"""
        
        # If no scan context provided, respond generally
        if not scan_context:
            return f"""{base_prompt}

USER QUESTION: {user_message}

Please answer the user's cybersecurity question briefly and helpfully."""
        
        # Extract scan data
        url = scan_context.get('url', 'Unknown URL')
        is_phishing = scan_context.get('is_phishing', False)
        confidence = scan_context.get('confidence_score', 0)
        threat_type = scan_context.get('threat_type', 'Unknown')
        
        # Extract OSINT data if available
        osint = scan_context.get('osint', {})
        domain = osint.get('domain', 'Unknown')
        server_location = osint.get('server_location', 'Unknown')
        isp = osint.get('isp', 'Unknown')
        registrar = osint.get('registrar', 'Unknown')
        domain_age_days = osint.get('domain_age_days')
        has_mail_server = osint.get('has_mail_server')
        
        # Build OSINT context string
        osint_info = ""
        if osint:
            osint_info = f"""
DOMAIN INTELLIGENCE:
- Domain: {domain}
- Server Location: {server_location}
- ISP/Hosting: {isp}
- Registrar: {registrar}
- Domain Age: {domain_age_days} days ({self._format_domain_age(domain_age_days)})
- Has Mail Server: {'Yes' if has_mail_server else 'No'}
"""
        
        # Determine risk indicators
        risk_indicators = []
        if is_phishing:
            risk_indicators.append(f"AI flagged as PHISHING ({confidence:.1f}% confidence)")
        
        if domain_age_days is not None:
            if domain_age_days < 7:
                risk_indicators.append(f"🚨 CRITICAL: Domain created only {domain_age_days} days ago")
            elif domain_age_days < 30:
                risk_indicators.append(f"⚠️ WARNING: Young domain ({domain_age_days} days old)")
            elif domain_age_days < 90:
                risk_indicators.append(f"ℹ️ INFO: Relatively new domain ({domain_age_days} days)")
        
        if not has_mail_server:
            risk_indicators.append("⚠️ No email server configured (unusual for legitimate sites)")
        
        risk_summary = "\n- ".join(risk_indicators) if risk_indicators else "No significant red flags detected"
        
        # Build detailed prompt
        prompt = f"""{base_prompt}

SCAN CONTEXT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
URL SCANNED: {url}
VERDICT: {"🚫 PHISHING DETECTED" if is_phishing else "✅ APPEARS SAFE"}
CONFIDENCE: {confidence:.1f}%
THREAT TYPE: {threat_type if threat_type else "None detected"}

{osint_info}

RISK INDICATORS:
- {risk_summary}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

USER QUESTION: {user_message}

Based on the scan results above, provide a clear and helpful answer to the user's question. 
Focus on what matters most for their security."""
        
        return prompt
    
    def _format_domain_age(self, days: Optional[int]) -> str:
        """Format domain age in human-readable format"""
        if days is None:
            return "Unknown"
        if days < 7:
            return "Brand new - HIGH RISK"
        elif days < 30:
            return "Very young - CAUTION"
        elif days < 90:
            return "Recent"
        elif days < 365:
            return "Less than a year"
        elif days < 730:
            return "About 1 year"
        elif days < 1825:
            return f"About {days // 365} years"
        else:
            return f"{days // 365}+ years - Well established"
    
    def get_response(
        self, 
        user_message: str, 
        scan_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Get AI response from Gemini
        
        Args:
            user_message: User's question
            scan_context: Scan results context (optional)
        
        Returns:
            Dictionary with response and metadata:
            {
                'success': bool,
                'response': str,
                'error': str (if failed)
            }
        """
        if not self.is_available:
            return {
                'success': False,
                'response': None,
                'error': 'Chatbot service is not available. Please configure GEMINI_API_KEY.'
            }
        
        try:
            # Construct prompt
            prompt = self.construct_prompt(user_message, scan_context)
            
            logger.info(f"Sending request to Gemini AI: {user_message[:100]}...")
            
            # Generate response
            response = self.model.generate_content(
                prompt,
                generation_config={
                    'temperature': 0.7,  # Balanced creativity
                    'top_p': 0.9,
                    'top_k': 40,
                    'max_output_tokens': 500,  # Limit response length
                }
            )
            
            # Extract text
            if response and response.text:
                logger.info("Successfully received response from Gemini")
                return {
                    'success': True,
                    'response': response.text.strip(),
                    'error': None
                }
            else:
                logger.warning("Empty response from Gemini")
                return {
                    'success': False,
                    'response': None,
                    'error': 'Received empty response from AI'
                }
                
        except Exception as e:
            logger.error(f"Error getting Gemini response: {e}")
            return {
                'success': False,
                'response': None,
                'error': f'Failed to get AI response: {str(e)}'
            }
    
    def get_quick_summary(self, scan_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get a quick automated summary without user question
        
        Args:
            scan_context: Scan results to summarize
        
        Returns:
            Dictionary with summary response
        """
        default_question = "Can you explain these scan results and whether I should trust this website?"
        return self.get_response(default_question, scan_context)


# Singleton instance
gemini_chatbot = GeminiChatbot()


def get_chatbot_response(
    message: str, 
    scan_context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to get chatbot response
    
    Args:
        message: User's message
        scan_context: Optional scan context
    
    Returns:
        Response dictionary from Gemini
    """
    return gemini_chatbot.get_response(message, scan_context)


def is_chatbot_available() -> bool:
    """Check if chatbot service is available"""
    return gemini_chatbot.is_available
