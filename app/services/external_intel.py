"""
Phishing Detector - External Intelligence Service
Integration with Google Safe Browsing API.
"""

import requests
import logging
from typing import Dict, Any, List
from app.config import settings

logger = logging.getLogger(__name__)

class ExternalIntel:
    """
    Wrapper for External Threat Intelligence APIs.
    """
    
    def __init__(self):
        self.gsb_key = settings.GOOGLE_SAFE_BROWSING_KEY
        self.gsb_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        
    def check_google_safe_browsing(self, url: str) -> Dict[str, Any]:
        """
        Check URL against Google Safe Browsing v4 API.
        Returns {'safe': bool, 'matches': list, 'source': 'Google Safe Browsing'}
        """
        if not self.gsb_key:
             logger.warning("[ExternalIntel] Google Safe Browsing Key missing. Skipping.")
             return {'safe': True, 'skipped': True}

        playload = {
            "client": {
                "clientId":      "phishing-detector",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        
        try:
            response = requests.post(self.gsb_url, params={'key': self.gsb_key}, json=playload, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            matches = data.get('matches', [])
            
            is_safe = len(matches) == 0
            
            if not is_safe:
                logger.warning(f"[ExternalIntel] Google Safe Browsing Hit: {url} -> {matches}")
                
            return {
                'safe': is_safe,
                'matches': matches,
                'source': 'Google Safe Browsing'
            }
            
        except Exception as e:
            logger.error(f"[ExternalIntel] GSB Check failed: {e}")
            return {'safe': True, 'error': str(e)}

# Singleton
external_intel = ExternalIntel()
