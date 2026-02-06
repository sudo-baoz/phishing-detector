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
from typing import Dict, Any, List, Tuple, Optional
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

    def check_typosquatting(self, url: str) -> Dict[str, Any]:
        """
        Check for Typosquatting/Homograph attacks using textdistance.
        User-defined high value targets.
        """
        try:
            import textdistance
        except ImportError:
            logger.warning("textdistance not installed, skipping typosquatting check")
            return {'risk': False}
            
        targets = [
            'facebook.com', 'google.com', 'paypal.com', 'binance.com', 
            'microsoft.com', 'netflix.com', 'instagram.com', 'tiktok.com'
        ]
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # Clean domain (remove www.)
        clean_domain = domain.replace('www.', '')
        
        # Mapping for 0->o, 1->l normalization for stricter check
        # But 'textdistance' handles edit distance. 
        # User asked for custom mapping if needed.
        # Let's do a basic normalization for the check
        normalized_domain = clean_domain.replace('0', 'o').replace('1', 'l').replace('rn', 'm').replace('vv', 'w')
        
        best_match = None
        max_sim = 0.0
        
        for target in targets:
            # Exact match is SAFE (it's the real brand)
            if clean_domain == target or clean_domain.endswith('.' + target):
                continue
                
            # Compare using textdistance
            # Using normalized_similarity (LCS or Levenshtein)
            # User specifically asked for: textdistance.levenshtein.normalized_similarity
            sim = textdistance.levenshtein.normalized_similarity(clean_domain, target)
            
            # Also compare with manually normalized version for homographs
            sim_norm = textdistance.levenshtein.normalized_similarity(normalized_domain, target)
            
            final_sim = max(sim, sim_norm)
            
            if final_sim > max_sim:
                max_sim = final_sim
                best_match = target
                
        # Logic: Similarity > 0.8 but NOT exact match (already handled by continue)
        is_risk = max_sim > 0.80
        
        if is_risk:
             logger.warning(f"[DeepScan] Typosquatting detected! {domain} ~ {best_match} ({max_sim:.2f})")
             return {
                 'risk': True,
                 'target': best_match,
                 'similarity': max_sim,
                 'verdict': 'PHISHING'
             }
             
        return {'risk': False, 'similarity': max_sim}

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

    
    # Reputable domains often used for Open Redirect attacks
    REPUTABLE_REDIRECTORS = {'youtube.com', 'google.com', 'facebook.com', 'linkedin.com', 't.co', 'bing.com'}

    def trace_redirects(self, url: str) -> Dict[str, Any]:
        """
        Follow HTTP redirect chain explicitly.
        Detect Open Redirect Abuse (Reputable -> Suspicious).
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            session = requests.Session()
            session.max_redirects = 10 # Prevent infinite loops
            
            # Use a custom user agent
            headers = {'User-Agent': 'Mozilla/5.0 Phishing-Scanner/1.0'}
            
            # Follow redirects manually or let requests do it and inspect history
            # Using requests history is cleaner for simple tracing
            response = session.head(url, allow_redirects=True, timeout=self.timeout, headers=headers)
            
            # Fallback to GET if HEAD rejected
            if response.status_code in [405, 403]:
                response = session.get(url, allow_redirects=True, timeout=self.timeout, headers=headers)

            history = response.history
            final_url = response.url
            hops = len(history)
            
            chain = [r.url for r in history]
            
            # Check for shorteners
            has_shortener = False
            trace_domains = [urlparse(u).netloc for u in chain + [final_url]]
            for d in trace_domains:
                clean_d = d.split(':')[0].lower()
                clean_d = clean_d.replace('www.', '')
                if any(clean_d.endswith(s) for s in self.SHORTENERS) or clean_d in self.SHORTENERS:
                    has_shortener = True
                    break
            
            # Open Redirect Analysis
            is_open_redirect = False
            initial_domain = urlparse(url).netloc.lower().replace('www.', '')
            final_domain = urlparse(final_url).netloc.lower().replace('www.', '')
            
            # Logic: Started at reputable redirector -> Ended at non-reputable
            if any(r in initial_domain for r in self.REPUTABLE_REDIRECTORS):
                # Check if final domain is NOT reputable (suspicious/generic)
                if not any(r in final_domain for r in self.REPUTABLE_REDIRECTORS):
                    is_open_redirect = True
                    logger.warning(f"[DeepScan] Open Redirect Abuse: {initial_domain} -> {final_domain}")

            # Risk logic
            is_risk = False
            risk_reasons = []
            
            if hops > 3:
                is_risk = True
                risk_reasons.append("Too many redirects")
            
            if has_shortener:
                is_risk = True
                risk_reasons.append("URL Shortener usage")
                
            if is_open_redirect:
                is_risk = True
                risk_reasons.append("Open Redirect Abuse (Reputable -> External)")
                
            return {
                'hops': hops,
                'final_url': final_url,
                'chain': chain,
                'has_shortener': has_shortener,
                'is_open_redirect': is_open_redirect,
                'risk': is_risk,
                'reasons': risk_reasons
            }
            
        except requests.TooManyRedirects:
             return {
                'hops': 10,
                'final_url': url, # Can't know final
                'chain': [],
                'has_shortener': False,
                'risk': True,
                'reasons': ["Infinite Redirect Loop Detected"],
                'error': "TooManyRedirects"
             }
        except requests.RequestException as e:
            logger.warning(f"[DeepScan] Redirect Trace failed: {e}")
            return {
                'hops': 0,
                'final_url': url, # Assume unchanged on error
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
             # Basic fetch to get HTML (reused for kit fingerprinting / YARA)
             response = requests.get(url, timeout=self.timeout)
             content = response.text
             # Cap size for kit/YARA use (e.g. 500KB) to avoid memory issues
             raw_html = content[:512000] if len(content) > 512000 else content

             # Extract script tags (Naive regex or parser)
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
                 'entropy_score': max_entropy,  # Frontend compatibility
                 'risk': risk,
                 'raw_html': raw_html,
             }
             
        except Exception:
            return {'max_js_entropy': 0.0, 'risk': False, 'raw_html': None}

    def analyze_security_headers(self, url: str) -> Dict[str, Any]:
        """
        Analyze HTTP security headers for the given URL.
        Missing critical headers indicate poor security posture (common in phishing sites).
        
        Args:
            url: URL to analyze
            
        Returns:
            Dict with score (0-100), missing_headers list, and details
        """
        # Critical security headers to check
        critical_headers = {
            'Strict-Transport-Security': 'HSTS - Enforces HTTPS connections',
            'Content-Security-Policy': 'CSP - Prevents XSS and injection attacks',
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME-type sniffing'
        }
        
        result = {
            'score': 100,
            'missing_headers': [],
            'present_headers': [],
            'details': {},
            'risk': False
        }
        
        try:
            # Try HEAD request first (faster), fallback to GET with stream
            try:
                response = requests.head(url, timeout=self.timeout, allow_redirects=True)
            except requests.exceptions.RequestException:
                # Some sites block HEAD requests, try GET with stream
                response = requests.get(url, timeout=self.timeout, allow_redirects=True, stream=True)
            
            headers = response.headers
            
            # Check each critical header
            for header, description in critical_headers.items():
                header_value = headers.get(header)
                
                if header_value:
                    result['present_headers'].append(header)
                    result['details'][header] = {
                        'present': True,
                        'value': header_value[:100],  # Truncate long values
                        'description': description
                    }
                else:
                    result['missing_headers'].append(header)
                    result['score'] -= 20  # Deduct 20 for each missing header
                    result['details'][header] = {
                        'present': False,
                        'value': None,
                        'description': description
                    }
            
            # Additional checks for bonus headers
            bonus_headers = ['X-XSS-Protection', 'Referrer-Policy', 'Permissions-Policy']
            for header in bonus_headers:
                if headers.get(header):
                    result['details'][header] = {
                        'present': True,
                        'value': headers.get(header)[:100] if headers.get(header) else None,
                        'bonus': True
                    }
            
            # Ensure score doesn't go below 0
            result['score'] = max(0, result['score'])
            
            # Flag as risk if score is low (missing 3+ critical headers)
            result['risk'] = result['score'] <= 40
            
            if result['risk']:
                logger.warning(f"[DeepScan] Poor security headers: {result['missing_headers']}")
                
        except requests.exceptions.Timeout:
            logger.warning(f"[DeepScan] Header analysis timeout for {url}")
            result['score'] = 50  # Unknown state
            result['details']['error'] = 'Request timeout'
            
        except requests.exceptions.SSLError as e:
            logger.warning(f"[DeepScan] SSL error during header analysis: {e}")
            result['score'] = 20  # SSL issues are very suspicious
            result['risk'] = True
            result['details']['error'] = f'SSL Error: {str(e)[:100]}'
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"[DeepScan] Header analysis failed: {e}")
            result['score'] = 50  # Unknown state
            result['details']['error'] = str(e)[:100]
            
        except Exception as e:
            logger.error(f"[DeepScan] Unexpected error in header analysis: {e}")
            result['score'] = 50
            result['details']['error'] = 'Unexpected error'
            
        return result

    def scan(self, url: str, existing_redirects: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform all deep scan heuristics and calculate Score.
        
        Args:
            url: URL to scan
            existing_redirects: Optional pre-calculated redirect trace (optimization)
            
        Returns:
            Dict containing scores and detailed breakdown.
        """
        parsed = urlparse(url)
        domain = parsed.netloc or url.split('/')[0]
        
        # 1. SSL Analysis
        ssl_res = self.analyze_ssl_age(domain)
        
        # 2. Redirect Analysis
        if existing_redirects:
            redirect_res = existing_redirects
        else:
            redirect_res = self.trace_redirects(url)
        
        # 3. Content/Entropy Analysis (Requires fetching)
        # We only do this if redirects didn't fail hard, using final URL
        final_url = redirect_res.get('final_url', url)
        # Check entropy on final URL
        entropy_res = self.analyze_page_content(final_url)
        
        # 4. Keyword Analysis
        keyword_res = self.analyze_keywords(url)
        
        # 5. Security Header Analysis
        header_res = self.analyze_security_headers(final_url)
        
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
            
        # Security headers penalty
        if header_res['risk']:
            score += 15  # Missing critical security headers
        
        # Cap at 100
        score = min(score, 100)

        # Expose raw HTML for Kit Fingerprinting and YARA (from content fetch above)
        raw_html = entropy_res.get('raw_html')

        return {
            'technical_risk_score': score,
            'details': {
                'ssl': ssl_res,
                'redirects': redirect_res,
                'content_entropy': {k: v for k, v in entropy_res.items() if k != 'raw_html'},
                'keywords': keyword_res,
                'security_headers': header_res
            },
            'raw_html': raw_html,
        }

# Singleton
deep_scanner = DeepScanner()
