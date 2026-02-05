"""
Phishing Detector - Deep Analysis Service
Copyright (c) 2026 BaoZ

Implements advanced heuristics for technical risk assessment:
1. SSL Certificate Age Analysis
2. JavaScript Entropy Calculation (Obfuscation Detection)
3. Redirect Chain Tracing
"""

import ssl
import socket
import math
import logging
import requests
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone
from urllib.parse import urlparse
from collections import Counter

logger = logging.getLogger(__name__)


class DeepScanner:
    """
    Deep Analysis Scanner for advanced threat heuristics.
    Generates a Technical Risk Score (0-100).
    """
    
    # Common URL shortener domains
    SHORTENERS = {
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 
        'buff.ly', 'adf.ly', 'bit.do', 'u.to', 'shorte.st', 'go2l.ink',
        'tr.im', '1url.com', 'cli.gs', 'yep.it', 'tiny.cc'
    }

    def __init__(self):
        self.timeout = 5  # Seconds for network requests
        
    def analyze_keywords(self, url: str) -> Dict[str, Any]:
        """
        Detect suspicious keywords in URL string.
        """
        suspicious_words = [
            'login', 'verify', 'update', 'banking', 'secure', 'account', 'signin', 
            'confirm', 'suspend', 'password', 'paypal', 'facebook', 'google', 
            'apple', 'microsoft', 'wallet', 'crypto', 'payment'
        ]
        
        url_lower = url.lower()
        found_keywords = [word for word in suspicious_words if word in url_lower]
        is_risk = len(found_keywords) > 0
        
        if is_risk:
            logger.warning(f"[DeepScan] Suspicious keywords found: {found_keywords}")
            
        return {
            'found': found_keywords,
            'risk': is_risk,
            'count': len(found_keywords)
        }

    def analyze_ssl_age(self, domain: str) -> Dict[str, Any]:
        """
        Check the age of the SSL certificate.
        Risk if certificate is younger than 48 hours (mostly used by fresh phishing sites).
        
        Args:
            domain (str): Domain name to check.
            
        Returns:
            Dict: {'age_hours': int, 'risk': bool, 'issuer': str}
        """
        try:
            # Remove protocol/path if present
            if '://' in domain:
                domain = domain.split('://')[1].split('/')[0]
            if '/' in domain:
                domain = domain.split('/')[0]
            if ':' in domain:  # Remove port
                domain = domain.split(':')[0]

            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            # Parse 'notBefore' field
            # Format usually: 'May 20 12:00:00 2025 GMT'
            not_before_str = cert['notBefore']
            not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
            not_before = not_before.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            age = now - not_before
            age_hours = age.total_seconds() / 3600
            
            # Simple issuer extraction
            issuer = dict(x[0] for x in cert['issuer'])
            common_name = issuer.get('commonName', 'Unknown')
            
            is_risk = age_hours < 48
            
            if is_risk:
                logger.warning(f"[DeepScan] Fresh SSL Certificate detected for {domain}: {age_hours:.1f} hours old")
                
            return {
                'age_hours': round(age_hours, 1),
                'risk': is_risk,
                'issuer': common_name,
                'error': None
            }
            
        except Exception as e:
            logger.warning(f"[DeepScan] SSL Analysis failed for {domain}: {e}")
            return {
                'age_hours': -1,
                'risk': False, # Assume safe if check fails to avoid blocking legitimate sites with bad config
                'issuer': None,
                'error': str(e)
            }

    def calculate_entropy(self, script_content: str) -> Dict[str, Any]:
        """
        Calculate Shannon Entropy of inline JavaScript.
        High entropy (> 5.5) indicates randomness/obfuscation (common in malware/phishing kits).
        
        Args:
            script_content (str): Content of the script tag.
            
        Returns:
            Dict: {'entropy': float, 'risk': bool}
        """
        if not script_content:
            return {'entropy': 0.0, 'risk': False}
            
        # Shannon Entropy Calculation
        counts = Counter(script_content)
        total_chars = len(script_content)
        
        entropy = 0.0
        for count in counts.values():
            p = count / total_chars
            entropy -= p * math.log2(p)
            
        # Threshold: 5.5 (Common for obfuscated/packed code)
        is_risk = entropy > 5.5
        
        if is_risk:
            logger.info(f"[DeepScan] High JS Entropy detected: {entropy:.2f}")
            
        return {
            'entropy': round(entropy, 2),
            'risk': is_risk
        }

    def trace_redirects(self, url: str) -> Dict[str, Any]:
        """
        Follow HTTP redirect chain.
        Risk if > 3 hops or uses known URL shorteners.
        
        Args:
            url (str): Starting URL.
            
        Returns:
            Dict: {'hops': int, 'final_url': str, 'has_shortener': bool, 'risk': bool}
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            response = requests.head(url, allow_redirects=True, timeout=self.timeout)
            
            # If method not allowed, try GET stream=True
            if response.status_code == 405:
                response = requests.get(url, allow_redirects=True, stream=True, timeout=self.timeout)

            history = response.history
            final_url = response.url
            hops = len(history)
            
            # Check for shorteners in the chain
            has_shortener = False
            trace_domains = [urlparse(url).netloc] + [urlparse(r.url).netloc for r in history] + [urlparse(final_url).netloc]
            
            for d in trace_domains:
                # Handle subdomains or port
                clean_d = d.split(':')[0].lower()
                if any(clean_d.endswith(s) for s in self.SHORTENERS) or clean_d in self.SHORTENERS:
                    has_shortener = True
                    break
            
            # Risk logic
            is_risk = False
            risk_reasons = []
            
            if hops > 3:
                is_risk = True
                risk_reasons.append("Too many redirects")
            
            if has_shortener:
                is_risk = True
                risk_reasons.append("URL Shortener usage")
                
            return {
                'hops': hops,
                'final_url': final_url,
                'chain': [r.url for r in history],
                'has_shortener': has_shortener,
                'risk': is_risk,
                'reasons': risk_reasons
            }
            
        except requests.RequestException as e:
            logger.warning(f"[DeepScan] Redirect Trace failed: {e}")
            return {
                'hops': 0,
                'final_url': url,
                'has_shortener': False,
                'risk': False,
                'error': str(e)
            }

    def analyze_page_content(self, url: str) -> Dict[str, Any]:
        """
        Fetch page content and analyze scripts entropy.
        
        Args:
            url (str): URL to fetch.
            
        Returns:
            Dict: Results of entropy analysis.
        """
        try:
             # Basic fetch to get HTML
             response = requests.get(url, timeout=self.timeout)
             content = response.text
             
             # Extract script tags (Naive regex or parser)
             # Use naive regex for lightweight dependency (avoid bs4 if possible, but bs4 is better)
             # assuming bs4 might not be installed, use re
             import re
             scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL)
             
             max_entropy = 0.0
             risk = False
             
             for script in scripts:
                 res = self.calculate_entropy(script)
                 if res['entropy'] > max_entropy:
                     max_entropy = res['entropy']
                 if res['risk']:
                     risk = True
             
             return {
                 'max_js_entropy': max_entropy,
                 'entropy_score': max_entropy, # Frontend combatibility
                 'risk': risk
             }
             
        except Exception:
            return {'max_js_entropy': 0.0, 'risk': False}

    def scan(self, url: str) -> Dict[str, Any]:
        """
        Perform all deep scan heuristics and calculate Score.
        
        Returns:
            Dict containing scores and detailed breakdown.
        """
        parsed = urlparse(url)
        domain = parsed.netloc or url.split('/')[0]
        
        # 1. SSL Analysis
        ssl_res = self.analyze_ssl_age(domain)
        
        # 2. Redirect Analysis
        redirect_res = self.trace_redirects(url)
        
        # 3. Content/Entropy Analysis (Requires fetching)
        # We only do this if redirects didn't fail hard, using final URL
        final_url = redirect_res.get('final_url', url)
        # Check entropy on final URL
        entropy_res = self.analyze_page_content(final_url)
        
        # 4. Keyword Analysis
        keyword_res = self.analyze_keywords(url)
        
        # --- Calculate Technical Risk Score (0-100) ---
        score = 0
        
        # Weights
        if ssl_res['risk']:
            score += 30  # Adjusted weight
            
        if entropy_res['risk']:
            score += 25  # Adjusted weight
            
        if keyword_res['risk']:
            score += 25  # New signal
            
        if redirect_res['hops'] > 3:
            score += 10
            
        if redirect_res['has_shortener']:
            score += 10
            
        # Cap at 100
        score = min(score, 100)
        
        return {
            'technical_risk_score': score,
            'details': {
                'ssl': ssl_res,
                'redirects': redirect_res,
                'content_entropy': entropy_res,
                'keywords': keyword_res
            }
        }

# Singleton
deep_scanner = DeepScanner()
