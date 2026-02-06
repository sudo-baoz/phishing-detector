"""
Phishing Detector - Network Forensics Service
Copyright (c) 2026 BaoZ

Implements Deep Network Analysis:
1. Domain Age (Whois Creation Date)
2. ASN Analysis (Cloud/Bulletproof Hosting detection)
"""

import whois
import socket
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from ipwhois import IPWhois
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class NetworkForensics:
    """
    Analyzes network-level indicators for phishing detection.
    Generates a Network Trust Score (0-100).
    """

    # Suspicious Keywords in Domain vs ASN Check
    # If domain contains these but is hosted on generic cloud options -> SUSPICIOUS
    SENSITIVE_KEYWORDS = {'bank', 'secure', 'login', 'account', 'verify', 'update', 'support', 'service', 'paypal', 'apple', 'google', 'microsoft'}

    # Cloud / Bulletproof Hosting ASNs (Simplified List)
    # Detection: If "bank-of-america-verify.com" is on DigitalOcean -> Phishing
    SUSPICIOUS_ASNS = {
        'DIGITALOCEAN', 'AMAZON', 'GOOGLE-CLOUD', 'MICROSOFT-CORP', 
        'CLOUDFLARE', 'HETZNER', 'OVH', 'CHOOPA', 'NAMECHEAP'
    }

    def get_domain_age(self, domain: str) -> Dict[str, Any]:
        """
        Get domain creation date and calculate age in days.
        Rule: < 30 days = High Risk.
        """
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            
            # Handle list of dates (some registrars return list)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if not creation_date:
                return {'age_days': None, 'risk': False, 'error': "No creation date found"}

            # Ensure UTC for comparison (naive fix)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            else:
                creation_date = creation_date.astimezone(timezone.utc)
                
            now = datetime.now(timezone.utc)
            age = now - creation_date
            age_days = age.days
            
            is_risk = age_days < 30
            
            if is_risk:
                logger.warning(f"[Network] Fresh Domain detected: {domain} ({age_days} days old)")
                
            return {
                'age_days': age_days,
                'creation_date': creation_date.strftime('%Y-%m-%d'),
                'risk': is_risk
            }
            
        except Exception as e:
            logger.debug(f"Whois lookup failed for {domain}: {e}")
            return {'age_days': None, 'risk': False, 'error': str(e)}

    def get_asn_info(self, domain: str) -> Dict[str, Any]:
        """
        Resolve IP and get ASN / Organization.
        Check for "Sensitive Domain on Cheap Cloud" pattern.
        """
        try:
            ip = socket.gethostbyname(domain)
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            
            asn_desc = results.get('asn_description', 'Unknown').upper()
            asn_id = results.get('asn', 'Unknown')
            
            # Risk Logic
            is_cloud = any(cloud in asn_desc for cloud in self.SUSPICIOUS_ASNS)
            
            domain_has_sensitive = any(kw in domain.lower() for kw in self.SENSITIVE_KEYWORDS)
            
            # If it claims to be a bank but looks like it's on a crude VPS -> Risk
            is_risk = is_cloud and domain_has_sensitive
            
            if is_risk:
                logger.warning(f"[Network] Suspicious Hosting detected: {domain} on {asn_desc}")

            return {
                'ip': ip,
                'asn': asn_id,
                'org': asn_desc,
                'is_cloud': is_cloud,
                'risk': is_risk
            }
            
        except Exception as e:
            logger.debug(f"ASN lookup failed for {domain}: {e}")
            return {'risk': False, 'error': str(e)}

    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Perform full network forensics.
        Returns Trust Score (0-100).
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # 1. Domain Age
        age_res = self.get_domain_age(domain)
        
        # 2. ASN Info
        asn_res = self.get_asn_info(domain)
        
        # --- Scoring (Trust Score: 100 = Safe, 0 = Toxic) ---
        # Start High
        score = 100
        
        # Penalties
        if age_res['risk']:
            score -= 50  # Heavy penalty for new domains
        elif age_res.get('age_days') and age_res['age_days'] < 90:
            score -= 20  # Moderate penalty for young domains
            
        if asn_res['risk']:
            score -= 40  # Mismatch hosting
            
        # Error handling (if checks fail, slightly reduce trust or neutral?)
        if age_res.get('error'):
            score -= 10 # Uncertainty penalty
            
        score = max(0, score)
        
        return {
            'network_trust_score': score,
            'details': {
                'domain_age': age_res,
                'hosting': asn_res
            }
        }

# Singleton
network_forensics = NetworkForensics()


# =============================================================================
# NETWORK TRAFFIC ANALYZER (XHR/Fetch exfiltration indicators)
# =============================================================================

# Signatures commonly used for credential exfiltration or C2
SUSPICIOUS_ENDPOINTS = [
    "api.telegram.org/bot",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "formsubmit.co",
    "googleusercontent.com",  # Sometimes abused for C2
    "webhook.site",
    "requestbin.com",
    "postman-echo.com",
    "pipedream.com",
    ".php",  # Generic PHP backend (login.php, save.php) - match as substring
]


class NetworkAnalyzer:
    """
    Analyzes captured XHR/Fetch traffic for exfiltration indicators.
    Phishing sites often POST stolen data to Telegram bots, Discord webhooks, or form handlers.
    """

    @staticmethod
    def _describe_destination(url: str) -> str:
        """Return a short human-readable description of the destination."""
        url_lower = url.lower()
        if "api.telegram.org" in url_lower and "/bot" in url_lower:
            return "Sending data to Telegram Bot API"
        if "discord.com/api/webhooks" in url_lower or "discordapp.com/api/webhooks" in url_lower:
            return "Sending data to Discord Webhook"
        if "formsubmit.co" in url_lower:
            return "Form submission to FormSubmit.co (often abused)"
        if "webhook.site" in url_lower:
            return "Sending data to Webhook.site (testing/exfiltration)"
        if "requestbin" in url_lower:
            return "Sending data to RequestBin"
        if ".php" in url_lower:
            return "POST to PHP backend (possible credential handler)"
        if "googleusercontent.com" in url_lower:
            return "Request to Google user content (possible C2)"
        return "Sending data to suspicious endpoint"

    @classmethod
    def analyze_traffic(cls, requests_list: list) -> Dict[str, Any]:
        """
        Analyze a list of captured requests (from VisionScanner) for exfiltration indicators.

        Args:
            requests_list: List of dicts with keys: url, method, post_data (optional)

        Returns:
            Dict with:
              - high_risk_findings: list of {url, method, destination_description, risk: "HIGH"}
              - total_captured: int
              - post_requests: int
              - exfiltration_detected: bool
        """
        high_risk_findings = []
        total_captured = len(requests_list)
        post_requests = 0

        for req in requests_list or []:
            url = (req.get("url") or "").strip()
            method = (req.get("method") or "GET").upper()
            if not url:
                continue
            if method == "POST":
                post_requests += 1

            url_lower = url.lower()
            matched = False
            for sig in SUSPICIOUS_ENDPOINTS:
                if sig.startswith("."):
                    if sig in url_lower:
                        matched = True
                        break
                elif sig in url_lower:
                    matched = True
                    break

            if matched and method == "POST":
                desc = cls._describe_destination(url)
                high_risk_findings.append({
                    "url": url[:500],
                    "method": method,
                    "destination_description": desc,
                    "risk": "HIGH",
                    "has_post_data": bool(req.get("post_data")),
                })

        exfiltration_detected = len(high_risk_findings) > 0
        if exfiltration_detected:
            logger.warning(
                "[NetworkAnalyzer] Exfiltration indicators: %d HIGH RISK request(s) (e.g. %s)",
                len(high_risk_findings),
                high_risk_findings[0].get("destination_description", "unknown"),
            )

        return {
            "high_risk_findings": high_risk_findings,
            "total_captured": total_captured,
            "post_requests": post_requests,
            "exfiltration_detected": exfiltration_detected,
        }
