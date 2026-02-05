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
