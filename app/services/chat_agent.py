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
Enhanced with God Mode Phishing Detection System
"""

import os
import re
import json
import logging
from typing import Dict, Any, Optional, List
import google.generativeai as genai
from app.config import settings
from app.core.prompts import GOD_MODE_SYSTEM_PROMPT
from app.services.osint_analyzer import get_deep_analyst

logger = logging.getLogger(__name__)


# =============================================================================
# GOD MODE PHISHING ANALYZER - Elite Threat Detection
# =============================================================================

class GodModeAnalyzer:
    """
    God Mode Phishing Analyzer using Gemini AI with specialized system prompt.
    Provides elite-level threat detection with structured JSON output.
    Includes quota limit handling for graceful degradation.
    """
    
    _instance = None
    _initialized = False
    
    # Quota tracking (class-level for singleton)
    _quota_exceeded = False
    _quota_exceeded_message = None
    
    # Default response structure for error cases
    DEFAULT_ERROR_RESPONSE = {
        "verdict": "SUSPICIOUS",
        "risk_score": 50,
        "summary": "Analysis failed due to an internal error. Manual review recommended.",
        "impersonation_target": None,
        "risk_factors": ["AI analysis unavailable"],
        "technical_analysis": {
            "url_integrity": "Unknown",
            "domain_age": "Unknown"
        },
        "recommendation": "Proceed with caution. Verify the URL manually before entering any sensitive information."
    }
    
    # Quota exceeded response (shown to users)
    QUOTA_EXCEEDED_RESPONSE = {
        "verdict": "UNKNOWN",
        "risk_score": 0,
        "summary": "⚠️ Tính năng phân tích AI tạm thời không khả dụng do giới hạn API. Chúng tôi sẽ cập nhật sớm.",
        "summary_en": "⚠️ AI analysis feature temporarily unavailable due to API limits. We will update soon.",
        "impersonation_target": None,
        "risk_factors": ["AI service quota exceeded"],
        "technical_analysis": {},
        "recommendation": "Vui lòng sử dụng kết quả phân tích ML và heuristics. / Please use ML and heuristics analysis results.",
        "quota_exceeded": True,
        "error": "API_QUOTA_EXCEEDED"
    }
    
    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            cls._instance = super(GodModeAnalyzer, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize Gemini model with God Mode system prompt"""
        if not self._initialized:
            self.model = None
            self._available = False
            
            try:
                api_key = settings.GEMINI_API_KEY
                
                if not api_key or api_key.strip() == "":
                    logger.warning("GEMINI_API_KEY not set. God Mode Analyzer will not be available.")
                    self._initialized = True
                    return
                
                # Configure Gemini API
                genai.configure(api_key=api_key)
                
                # Initialize with God Mode system prompt and JSON output
                generation_config = genai.GenerationConfig(
                    response_mime_type="application/json"
                )
                
                self.model = genai.GenerativeModel(
                    model_name="gemini-2.5-flash",
                    system_instruction=GOD_MODE_SYSTEM_PROMPT,
                    generation_config=generation_config
                )
                
                self._available = True
                logger.info("[OK] God Mode Analyzer initialized with gemini-1.5-flash")
                
            except Exception as e:
                logger.error(f"Failed to initialize God Mode Analyzer: {e}")
                self.model = None
                self._available = False
            
            self._initialized = True
    
    def is_available(self) -> bool:
        """Check if God Mode Analyzer is available (not quota exceeded)"""
        if self._quota_exceeded:
            return False
        return self._available and self.model is not None
    
    def is_quota_exceeded(self) -> bool:
        """Check if API quota has been exceeded"""
        return self._quota_exceeded
    
    def get_quota_message(self) -> Optional[str]:
        """Get quota exceeded message if any"""
        return self._quota_exceeded_message
    
    def analyze(
        self,
        url: str,
        dom_text: Optional[str] = None,
        deep_tech_data: Optional[Dict[str, Any]] = None,
        rag_context: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Perform God Mode analysis on a URL with optional context.
        
        Args:
            url: The URL to analyze
            dom_text: Optional page DOM/content text
            deep_tech_data: Optional technical analysis data (SSL, headers, etc.)
            rag_context: Optional RAG context from knowledge base
            
        Returns:
            Structured JSON analysis result
        """
        if not self.is_available():
            # Return quota exceeded response if that's the reason
            if self._quota_exceeded:
                logger.warning("[GOD MODE] Skipped - API quota exceeded")
                return self.QUOTA_EXCEEDED_RESPONSE.copy()
            
            logger.warning("God Mode Analyzer not available")
            return {**self.DEFAULT_ERROR_RESPONSE, "error": "AI service unavailable"}
        
        try:
            # Build comprehensive user prompt
            user_prompt = self._build_analysis_prompt(url, dom_text, deep_tech_data, rag_context)
            
            logger.debug(f"[GOD MODE] Analyzing URL: {url}")
            logger.debug(f"[GOD MODE] Prompt length: {len(user_prompt)} chars")
            
            # Generate response from Gemini
            response = self.model.generate_content(user_prompt)
            
            # Parse JSON response
            result = self._parse_response(response.text)
            
            logger.debug(f"[GOD MODE] Analysis complete - Verdict: {result.get('verdict', 'UNKNOWN')}")
            return result
            
        except Exception as e:
            error_str = str(e).lower()
            
            # Detect quota/rate limit errors
            quota_keywords = [
                'quota', 'rate limit', 'resource exhausted', 
                '429', 'too many requests', 'billing', 
                'quota exceeded', 'limit exceeded'
            ]
            
            if any(keyword in error_str for keyword in quota_keywords):
                # Mark quota as exceeded (disable further calls)
                self._quota_exceeded = True
                self._quota_exceeded_message = str(e)[:200]
                logger.error(f"[GOD MODE] API QUOTA EXCEEDED - Disabling service: {e}")
                return self.QUOTA_EXCEEDED_RESPONSE.copy()
            
            logger.error(f"God Mode analysis failed: {e}")
            return {
                **self.DEFAULT_ERROR_RESPONSE,
                "error": str(e)[:100],
                "summary": f"Analysis failed: {str(e)[:100]}"
            }
    
    def _build_analysis_prompt(
        self,
        url: str,
        dom_text: Optional[str],
        deep_tech_data: Optional[Dict[str, Any]],
        rag_context: Optional[List[Dict[str, Any]]]
    ) -> str:
        """Build the user prompt for God Mode analysis"""
        
        prompt_parts = [f"=== TARGET URL ===\n{url}"]

        # OSINT: Domain age, registrar, SSL (evidence-based; scammers cannot fake these)
        try:
            osint_result = get_deep_analyst().analyze_domain(url)
            osint_json = json.dumps(osint_result, indent=2, default=str)
            prompt_parts.append(f"\n=== OSINT DATA (Domain Age, Registrar, SSL) ===\n{osint_json}")
        except Exception as e:
            logger.debug("DeepAnalyst OSINT failed: %s", e)
            prompt_parts.append("\n=== OSINT DATA ===\n{\"error\": \"OSINT lookup failed\", \"risk_factors\": [\"WARNING: OSINT unavailable.\"]}")
        
        # Add DOM content if available
        if dom_text:
            # Truncate DOM to prevent token overflow
            truncated_dom = dom_text[:3000] if len(dom_text) > 3000 else dom_text
            prompt_parts.append(f"\n=== PAGE CONTENT (DOM) ===\n{truncated_dom}")
        
        # Add technical data if available
        if deep_tech_data:
            tech_str = json.dumps(deep_tech_data, indent=2, default=str)
            prompt_parts.append(f"\n=== TECHNICAL ANALYSIS ===\n{tech_str}")
        
        # Add RAG context if available (threat intelligence)
        if rag_context and len(rag_context) > 0:
            prompt_parts.append("\n=== THREAT INTELLIGENCE (RAG) ===")
            for i, threat in enumerate(rag_context[:3]):  # Limit to top 3
                similarity = threat.get('similarity_score', 0) * 100
                target = threat.get('target', 'Unknown')
                similar_url = threat.get('similar_url', 'N/A')
                prompt_parts.append(
                    f"\n[Match {i+1}] {similarity:.1f}% similarity to known threat"
                    f"\n  - Target Brand: {target}"
                    f"\n  - Known Threat URL: {similar_url}"
                )
        
        prompt_parts.append("\n\n=== ANALYSIS REQUEST ===")
        prompt_parts.append("Combine the OSINT data (domain age, registrar, SSL) with the URL, page content, and threat intelligence above.")
        prompt_parts.append("Perform evidence-based phishing analysis. Return your verdict as structured JSON.")
        
        return "\n".join(prompt_parts)
    
    def _parse_response(self, response_text: str) -> Dict[str, Any]:
        """Parse and validate the AI response"""
        try:
            # Clean response text (remove markdown code blocks if present)
            clean_text = response_text.strip()
            if clean_text.startswith("```json"):
                clean_text = clean_text[7:]
            if clean_text.startswith("```"):
                clean_text = clean_text[3:]
            if clean_text.endswith("```"):
                clean_text = clean_text[:-3]
            clean_text = clean_text.strip()
            
            result = json.loads(clean_text)
            
            # Validate required fields
            required_fields = ["verdict", "risk_score", "summary"]
            for field in required_fields:
                if field not in result:
                    result[field] = self.DEFAULT_ERROR_RESPONSE.get(field)
            
            # Normalize verdict
            if result.get("verdict") not in ["SAFE", "SUSPICIOUS", "PHISHING"]:
                result["verdict"] = "SUSPICIOUS"
            
            # Ensure risk_score is valid
            try:
                result["risk_score"] = max(0, min(100, int(result.get("risk_score", 50))))
            except (ValueError, TypeError):
                result["risk_score"] = 50
            
            return result
            
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse AI response as JSON: {e}")
            # Return structured response with raw text
            return {
                **self.DEFAULT_ERROR_RESPONSE,
                "summary": response_text[:500],
                "raw_response": response_text
            }


# Global God Mode Analyzer instance
god_mode_analyzer = GodModeAnalyzer()


def analyze_url_god_mode(
    url: str,
    dom_text: Optional[str] = None,
    deep_tech_data: Optional[Dict[str, Any]] = None,
    rag_context: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Convenience function for God Mode URL analysis.
    
    Args:
        url: URL to analyze
        dom_text: Optional page content
        deep_tech_data: Optional technical data
        rag_context: Optional RAG threat intelligence
        
    Returns:
        Structured analysis result
    """
    return god_mode_analyzer.analyze(url, dom_text, deep_tech_data, rag_context)


def is_god_mode_available() -> bool:
    """Check if God Mode Analyzer is available"""
    return god_mode_analyzer.is_available()


def is_quota_exceeded() -> bool:
    """Check if API quota has been exceeded"""
    return god_mode_analyzer.is_quota_exceeded()


def get_quota_status() -> Dict[str, Any]:
    """Get current quota status for API responses"""
    return {
        "available": god_mode_analyzer.is_available(),
        "quota_exceeded": god_mode_analyzer.is_quota_exceeded(),
        "message": god_mode_analyzer.get_quota_message()
    }


# =============================================================================
# ORIGINAL SENTINEL AI (Preserved for backward compatibility)
# =============================================================================


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
    
    def analyze_homograph(self, url: str) -> Dict[str, Any]:
        """
        Specialized analysis for Homograph & Typosquatting attacks
        Returns structured JSON verdict
        """
        if not self.is_available():
             return {"error": "AI not available"}

        prompt = f"""Act as an Elite Cyber Security Analyst specialized in Homograph & Typosquatting Attacks.

Your Mission: Analyze the provided URL strictly for impersonation attempts.

CRITICAL RULE: Do NOT read the URL like a human. Read it like a machine.

Step 1: Brand Impersonation Check (The 'faceb00k' Rule)

Compare the input domain against this Protected Brand List: ['facebook.com', 'google.com', 'binance.com', 'paypal.com', 'microsoft.com', 'netflix.com', 'instagram.com', 'tiktok.com'].

Homograph Detection: Look for visual look-alikes:
'0' (zero) instead of 'o' (letter).
'1' (one) or 'I' (capital i) instead of 'l' (letter L).
'rn' instead of 'm'.
'vv' instead of 'w'.

Verdict Logic: If the domain looks visually similar (>80%) to a Protected Brand but is NOT the exact official domain, verify immediately as PHISHING (High Confidence).

Step 2: Subdomain Abuse

Check if the brand name is in the subdomain (e.g., facebook.verify-account.com). This is PHISHING.

Step 3: AI Verdict

Input: {url}

If you detect 'faceb00k', 'googIe', 'paypaI' -> FLAG AS PHISHING IMMEDIATELY. Do not hesitate.

Response Format (JSON): {{ 'verdict': 'PHISHING', 'risk_score': 100, 'reason': 'Homograph Attack Detected...', 'impersonation_target': 'Facebook' }}
Else: {{ 'verdict': 'SAFE', 'risk_score': 0, 'reason': 'No homograph detected', 'impersonation_target': None }}
"""
        try:
            response = self.model.generate_content(prompt)
            # Clean response to ensure valid JSON (sometimes AI adds backticks)
            text = response.text.replace('```json', '').replace('```', '').strip()
            
            # Simple manual parse or return text if complex
            import json
            try:
                result = json.loads(text)
                return result
            except json.JSONDecodeError:
                return {"verdict": "ERROR", "raw_response": text}
                
        except Exception as e:
            logger.error(f"Homograph analysis failed: {e}")
            return {"error": str(e)}

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
