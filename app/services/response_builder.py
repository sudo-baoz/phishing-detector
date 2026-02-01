"""
Response Builder Service
Builds detailed scan response according to new schema
"""

import logging
import re
import ssl
import socket
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)


# Known brands for impersonation detection
KNOWN_BRANDS = {
    'facebook': ['facebook', 'fb', 'meta'],
    'google': ['google', 'gmail', 'docs', 'drive'],
    'paypal': ['paypal', 'pp'],
    'amazon': ['amazon', 'amzn', 'aws'],
    'microsoft': ['microsoft', 'office', 'outlook', 'live'],
    'apple': ['apple', 'icloud', 'itunes'],
    'netflix': ['netflix', 'nflx'],
    'instagram': ['instagram', 'insta', 'ig'],
    'twitter': ['twitter', 'x'],
    'linkedin': ['linkedin'],
    'whatsapp': ['whatsapp', 'wa'],
    'telegram': ['telegram', 'tg'],
    'bank': ['bank', 'banking', 'hsbc', 'citibank', 'chase']
}


class ResponseBuilder:
    """Builds enhanced scan responses"""
    
    @staticmethod
    def calculate_risk_level(confidence_score: float, is_phishing: bool) -> str:
        """
        Calculate risk level based on confidence score
        
        Args:
            confidence_score: Confidence score (0-100)
            is_phishing: Whether URL is phishing
            
        Returns:
            Risk level: LOW, MEDIUM, HIGH, CRITICAL
        """
        if not is_phishing:
            return "LOW"
        
        if confidence_score >= 90:
            return "CRITICAL"
        elif confidence_score >= 75:
            return "HIGH"
        elif confidence_score >= 50:
            return "MEDIUM"
        else:
            return "LOW"
    
    @staticmethod
    def apply_heuristic_scoring(
        base_score: float,
        domain_age_days: Optional[int],
        redirect_count: int,
        has_suspicious_content: bool
    ) -> float:
        """
        Apply heuristic rules to adjust risk score
        
        Args:
            base_score: Base ML model score
            domain_age_days: Domain age in days
            redirect_count: Number of redirects
            has_suspicious_content: Whether suspicious content detected
            
        Returns:
            Adjusted risk score (0-100)
        """
        adjusted_score = base_score
        
        # Rule 1: Very young domain (<7 days) increases risk
        if domain_age_days is not None and domain_age_days < 7:
            adjusted_score += 20
            logger.info(f"[Heuristic] Domain age < 7 days: +20 risk")
        
        # Rule 2: Domain age 7-30 days increases risk moderately
        elif domain_age_days is not None and domain_age_days < 30:
            adjusted_score += 10
            logger.info(f"[Heuristic] Domain age < 30 days: +10 risk")
        
        # Rule 3: Multiple redirects increase risk
        if redirect_count > 2:
            adjusted_score += 15
            logger.info(f"[Heuristic] {redirect_count} redirects: +15 risk")
        elif redirect_count > 0:
            adjusted_score += 5
            logger.info(f"[Heuristic] {redirect_count} redirects: +5 risk")
        
        # Rule 4: Suspicious content (password forms, bot APIs) increases risk
        if has_suspicious_content:
            adjusted_score += 10
            logger.info(f"[Heuristic] Suspicious content detected: +10 risk")
        
        # Cap at 100
        return min(adjusted_score, 100.0)
    
    @staticmethod
    def detect_target_brand(url: str, threat_type: Optional[str]) -> Optional[str]:
        """
        Detect which brand the phishing site is impersonating
        
        Args:
            url: URL to analyze
            threat_type: Type of threat
            
        Returns:
            Brand name if detected
        """
        url_lower = url.lower()
        
        for brand, keywords in KNOWN_BRANDS.items():
            if any(keyword in url_lower for keyword in keywords):
                return brand.capitalize()
        
        return None
    
    @staticmethod
    def detect_typosquatting(url: str) -> bool:
        """
        Detect typosquatting patterns
        
        Args:
            url: URL to analyze
            
        Returns:
            True if typosquatting detected
        """
        url_lower = url.lower()
        
        # Common typosquatting patterns
        patterns = [
            r'faceb[o0][o0]k',  # facebook
            r'g[o0][o0]gle',     # google
            r'paypa[l1]',        # paypal
            r'amaz[o0]n',        # amazon
            r'micr[o0]s[o0]ft',  # microsoft
            r'app[l1]e',         # apple
            r'netf[l1]ix',       # netflix
        ]
        
        for pattern in patterns:
            if re.search(pattern, url_lower):
                # Check if it's NOT the real domain
                if not any(real in url_lower for real in ['facebook.com', 'google.com', 'paypal.com', 
                                                           'amazon.com', 'microsoft.com', 'apple.com', 'netflix.com']):
                    return True
        
        return False
    
    @staticmethod
    def detect_obfuscation(url: str) -> Optional[str]:
        """
        Detect URL obfuscation techniques
        
        Args:
            url: URL to analyze
            
        Returns:
            Obfuscation type if detected
        """
        try:
            parsed = urlparse(url)
            
            # Check for IP address usage
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc):
                return "IP Usage detected"
            
            # Check for URL encoding
            if '%' in url and any(x in url for x in ['%2F', '%3A', '%40']):
                return "URL encoding detected"
            
            # Check for excessive subdomains
            if parsed.netloc.count('.') > 3:
                return "Excessive subdomains"
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq', '.top', '.club']
            if any(url.endswith(tld) for tld in suspicious_tlds):
                return f"Suspicious TLD: {[tld for tld in suspicious_tlds if url.endswith(tld)][0]}"
            
        except:
            pass
        
        return None
    
    @staticmethod
    def format_domain_age(age_days: Optional[int]) -> Optional[str]:
        """
        Format domain age in human-readable format
        
        Args:
            age_days: Age in days
            
        Returns:
            Formatted age string
        """
        if age_days is None:
            return None
        
        if age_days < 1:
            return "< 1 day"
        elif age_days == 1:
            return "1 day"
        elif age_days < 7:
            return f"{age_days} days"
        elif age_days < 30:
            weeks = age_days // 7
            return f"{weeks} week{'s' if weeks > 1 else ''}"
        elif age_days < 365:
            months = age_days // 30
            return f"{months} month{'s' if months > 1 else ''}"
        else:
            years = age_days // 365
            return f"{years} year{'s' if years > 1 else ''}"
    
    @staticmethod
    def build_verdict(
        is_phishing: bool,
        confidence_score: float,
        threat_type: Optional[str],
        url: str
    ) -> Dict[str, Any]:
        """Build verdict data"""
        risk_level = ResponseBuilder.calculate_risk_level(confidence_score, is_phishing)
        target_brand = ResponseBuilder.detect_target_brand(url, threat_type) if is_phishing else None
        
        # Convert confidence to risk score (invert if safe)
        if is_phishing:
            risk_score = int(confidence_score)
        else:
            # If safe, risk score is inverse (high confidence safe = low risk)
            risk_score = int(100 - confidence_score)
        
        return {
            "score": risk_score,
            "level": risk_level,
            "target_brand": target_brand,
            "threat_type": threat_type
        }
    
    @staticmethod
    def build_network(osint_data: Optional[Dict[str, Any]], url: str) -> Dict[str, Any]:
        """Build network data"""
        if not osint_data:
            return {
                "domain_age": None,
                "registrar": None,
                "isp": None,
                "country": None,
                "ip": None
            }
        
        domain_age = ResponseBuilder.format_domain_age(osint_data.get('domain_age_days'))
        
        return {
            "domain_age": domain_age,
            "registrar": osint_data.get('registrar'),
            "isp": osint_data.get('isp'),
            "country": osint_data.get('server_location'),
            "ip": osint_data.get('ip')
        }
    
    @staticmethod
    def detect_redirect_chain(url: str, timeout: int = 5) -> List[str]:
        """
        Detect redirect chain by following HTTP redirects
        
        Args:
            url: URL to analyze
            timeout: Request timeout in seconds
            
        Returns:
            List of URLs in redirect chain
        """
        redirect_chain = []
        try:
            # Use requests to follow redirects
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            # Get redirect history
            if response.history:
                for resp in response.history:
                    redirect_chain.append(resp.url)
                redirect_chain.append(response.url)  # Final URL
                logger.info(f"[Forensics] Detected {len(response.history)} redirects")
            else:
                redirect_chain = [url]  # No redirects
                
        except Exception as e:
            logger.warning(f"Failed to detect redirects: {e}")
            redirect_chain = [url]
        
        return redirect_chain
    
    @staticmethod
    def build_forensics(url: str) -> Dict[str, Any]:
        """Build forensics data"""
        typosquatting = ResponseBuilder.detect_typosquatting(url)
        obfuscation = ResponseBuilder.detect_obfuscation(url)
        redirect_chain = ResponseBuilder.detect_redirect_chain(url)
        
        return {
            "typosquatting": typosquatting,
            "redirect_chain": redirect_chain if len(redirect_chain) > 1 else None,
            "obfuscation": obfuscation
        }
    
    @staticmethod
    def detect_password_fields(url: str, timeout: int = 5) -> bool:
        """
        Detect password input fields in HTML content
        
        Args:
            url: URL to analyze
            timeout: Request timeout in seconds
            
        Returns:
            True if password field detected
        """
        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            html_content = response.text.lower()
            
            # Check for password input fields
            password_patterns = [
                r'<input[^>]*type=["\']password["\']',
                r'<input[^>]*name=["\']password["\']',
                r'<input[^>]*id=["\']password["\']',
                r'<input[^>]*placeholder=["\'][^"\'\']*password[^"\'\']*["\']'
            ]
            
            for pattern in password_patterns:
                if re.search(pattern, html_content):
                    logger.info(f"[Content] Password field detected")
                    return True
            
        except Exception as e:
            logger.warning(f"Failed to detect password fields: {e}")
        
        return False
    
    @staticmethod
    def build_content(url: str) -> Dict[str, Any]:
        """Build content data"""
        has_login_form = ResponseBuilder.detect_password_fields(url)
        
        return {
            "has_login_form": has_login_form,
            "screenshot_url": None,  # TODO: Implement screenshot capture
            "external_resources": None  # TODO: Implement resource extraction
        }
    
    @staticmethod
    def detect_bot_apis(url: str, timeout: int = 5) -> Dict[str, bool]:
        """
        Detect Telegram bot API and Discord webhooks in HTML content
        
        Args:
            url: URL to analyze
            timeout: Request timeout in seconds
            
        Returns:
            Dict with telegram and discord detection results
        """
        result = {'telegram': False, 'discord': False}
        
        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            html_content = response.text.lower()
            
            # Check for Telegram bot API
            if re.search(r'api\.telegram\.org/bot', html_content):
                result['telegram'] = True
                logger.info(f"[Advanced] Telegram bot API detected")
            
            # Check for Discord webhooks
            if re.search(r'discord\.com/api/webhooks', html_content):
                result['discord'] = True
                logger.info(f"[Advanced] Discord webhook detected")
            
        except Exception as e:
            logger.warning(f"Failed to detect bot APIs: {e}")
        
        return result
    
    @staticmethod
    def get_ssl_certificate(url: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """
        Get SSL certificate details
        
        Args:
            url: URL to analyze
            timeout: Connection timeout in seconds
            
        Returns:
            Dict with ssl_issuer and ssl_validity
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract issuer
                    issuer = dict(x[0] for x in cert.get('issuer', ()))
                    ssl_issuer = issuer.get('organizationName', 'Unknown')
                    
                    # Extract validity period
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry_date - datetime.utcnow()).days
                        ssl_validity = f"Valid for {days_left} days" if days_left > 0 else "Expired"
                    else:
                        ssl_validity = "Unknown"
                    
                    logger.info(f"[Advanced] SSL: {ssl_issuer}, {ssl_validity}")
                    return {
                        'ssl_issuer': ssl_issuer,
                        'ssl_validity': ssl_validity
                    }
        
        except Exception as e:
            logger.warning(f"Failed to get SSL certificate: {e}")
        
        return None
    
    @staticmethod
    def build_advanced(url: str) -> Dict[str, Any]:
        """Build advanced data"""
        bot_apis = ResponseBuilder.detect_bot_apis(url)
        ssl_info = ResponseBuilder.get_ssl_certificate(url)
        
        telegram_detected = bot_apis['telegram'] or 'telegram' in url.lower() or 't.me' in url.lower()
        
        return {
            "telegram_bot_detected": telegram_detected,
            "discord_webhook_detected": bot_apis['discord'],
            "ssl_issuer": ssl_info['ssl_issuer'] if ssl_info else None,
            "ssl_validity": ssl_info['ssl_validity'] if ssl_info else None
        }
    
    @staticmethod
    def build_intelligence() -> Dict[str, Any]:
        """Build intelligence data"""
        # TODO: Integrate with VirusTotal and Google Safe Browsing APIs
        return {
            "virustotal_score": None,
            "google_safebrowsing": None
        }
    
    @staticmethod
    def build_complete_response(
        scan_id: int,
        url: str,
        scanned_at: datetime,
        is_phishing: bool,
        confidence_score: float,
        threat_type: Optional[str],
        osint_data: Optional[Dict[str, Any]] = None,
        deep_analysis: bool = True
    ) -> Dict[str, Any]:
        """
        Build complete scan response with deep analysis
        
        Args:
            scan_id: Database scan record ID
            url: Scanned URL
            scanned_at: Scan timestamp
            is_phishing: Whether URL is phishing
            confidence_score: Confidence score (0-100)
            threat_type: Type of threat
            osint_data: OSINT enrichment data
            deep_analysis: Whether to perform deep analysis (redirect, content, SSL)
            
        Returns:
            Complete response dictionary with 6 sections
        """
        logger.info(f"Building response for {url} (deep_analysis={deep_analysis})")
        
        # Build forensics (includes redirect chain detection)
        forensics = ResponseBuilder.build_forensics(url) if deep_analysis else {
            "typosquatting": ResponseBuilder.detect_typosquatting(url),
            "redirect_chain": None,
            "obfuscation": ResponseBuilder.detect_obfuscation(url)
        }
        
        # Build content (includes password field detection)
        content = ResponseBuilder.build_content(url) if deep_analysis else {
            "has_login_form": None,
            "screenshot_url": None,
            "external_resources": None
        }
        
        # Build advanced (includes bot API and SSL detection)
        advanced = ResponseBuilder.build_advanced(url) if deep_analysis else {
            "telegram_bot_detected": 'telegram' in url.lower() or 't.me' in url.lower(),
            "discord_webhook_detected": None,
            "ssl_issuer": None,
            "ssl_validity": None
        }
        
        # Apply heuristic scoring if deep analysis enabled
        final_score = confidence_score
        if deep_analysis and is_phishing:
            domain_age_days = osint_data.get('domain_age_days') if osint_data else None
            redirect_count = len(forensics.get('redirect_chain', [])) - 1 if forensics.get('redirect_chain') else 0
            has_suspicious_content = content.get('has_login_form', False) or advanced.get('telegram_bot_detected', False) or advanced.get('discord_webhook_detected', False)
            
            final_score = ResponseBuilder.apply_heuristic_scoring(
                base_score=confidence_score,
                domain_age_days=domain_age_days,
                redirect_count=redirect_count,
                has_suspicious_content=has_suspicious_content
            )
            logger.info(f"[Heuristic] Score adjusted: {confidence_score:.1f} → {final_score:.1f}")
        
        return {
            "id": scan_id,
            "url": url,
            "scanned_at": scanned_at,
            "verdict": ResponseBuilder.build_verdict(is_phishing, final_score, threat_type, url),
            "network": ResponseBuilder.build_network(osint_data, url),
            "forensics": forensics,
            "content": content,
            "advanced": advanced,
            "intelligence": ResponseBuilder.build_intelligence()
        }


# Global instance
response_builder = ResponseBuilder()
