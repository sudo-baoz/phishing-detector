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
Real-time CertStream Hunter - Zero-Day Phishing Detection
Monitors Certificate Transparency logs for suspicious domain registrations
"""

import logging
import threading
from typing import Set, Optional
from urllib.parse import urlparse
import certstream
import textdistance

logger = logging.getLogger(__name__)

# =============================================================================
# TARGET KEYWORDS - Brands and suspicious patterns to watch
# =============================================================================

TARGET_KEYWORDS = [
    # Big Tech
    'paypal', 'facebook', 'google', 'microsoft', 'apple', 'amazon',
    'netflix', 'instagram', 'tiktok', 'twitter', 'linkedin', 'whatsapp',
    # Financial
    'bank', 'crypto', 'binance', 'coinbase', 'metamask', 'wallet',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
    # Suspicious patterns
    'login', 'verify', 'secure', 'account', 'update', 'confirm',
    'signin', 'password', 'credential', 'authenticate',
    # E-commerce
    'ebay', 'alibaba', 'shopify', 'stripe',
    # Email providers
    'outlook', 'gmail', 'yahoo', 'protonmail',
]

# Additional homograph patterns (visual look-alikes)
HOMOGRAPH_PATTERNS = {
    '0': 'o',  # zero for letter o
    '1': 'l',  # one for letter l
    '1': 'i',  # one for letter i
    'rn': 'm',  # rn looks like m
    'vv': 'w',  # vv looks like w
}

# =============================================================================
# SUSPICIOUS DOMAIN CACHE
# =============================================================================

# Global cache for suspicious domains (thread-safe set operations)
SUSPICIOUS_CACHE: Set[str] = set()
CACHE_MAX_SIZE = 5000

# Lock for thread-safe cache operations
_cache_lock = threading.Lock()

# Monitor state
_monitor_running = False
_monitor_thread: Optional[threading.Thread] = None


def _add_to_cache(domain: str) -> None:
    """Add a domain to the suspicious cache (thread-safe)"""
    global SUSPICIOUS_CACHE
    
    with _cache_lock:
        # Prevent memory leak by limiting cache size
        if len(SUSPICIOUS_CACHE) >= CACHE_MAX_SIZE:
            # Remove oldest entries (convert to list, slice, convert back)
            SUSPICIOUS_CACHE = set(list(SUSPICIOUS_CACHE)[CACHE_MAX_SIZE // 2:])
            logger.info(f"[CERTSTREAM] Cache trimmed to {len(SUSPICIOUS_CACHE)} entries")
        
        SUSPICIOUS_CACHE.add(domain.lower())


def _is_suspicious_domain(domain: str) -> bool:
    """
    Check if a domain contains suspicious keywords or patterns.
    
    Args:
        domain: Domain name to check
        
    Returns:
        True if domain is suspicious
    """
    domain_lower = domain.lower()
    
    # Direct keyword match
    for keyword in TARGET_KEYWORDS:
        if keyword in domain_lower:
            return True
    
    # Homograph detection using Jaro-Winkler similarity
    # Check against known brand domains
    brand_domains = ['paypal.com', 'facebook.com', 'google.com', 'microsoft.com',
                     'apple.com', 'amazon.com', 'netflix.com', 'binance.com']
    
    for brand in brand_domains:
        # Calculate similarity
        similarity = textdistance.jaro_winkler(domain_lower, brand)
        if 0.75 < similarity < 1.0:  # Similar but not exact match
            logger.debug(f"[HOMOGRAPH] {domain} is {similarity:.2%} similar to {brand}")
            return True
    
    return False


def _certstream_callback(message: dict, context: dict) -> None:
    """
    Callback function for CertStream messages.
    Processes new certificate registrations and flags suspicious domains.
    
    Args:
        message: CertStream message containing certificate data
        context: CertStream context (unused)
    """
    try:
        if message.get('message_type') != 'certificate_update':
            return
        
        # Extract domain names from certificate
        data = message.get('data', {})
        leaf_cert = data.get('leaf_cert', {})
        all_domains = leaf_cert.get('all_domains', [])
        
        for domain in all_domains:
            # Skip wildcard domains
            if domain.startswith('*.'):
                domain = domain[2:]
            
            # Check if domain is suspicious
            if _is_suspicious_domain(domain):
                _add_to_cache(domain)
                logger.info(f"[CERTSTREAM] Suspicious domain detected: {domain}")
                
    except Exception as e:
        # Don't let callback errors crash the monitor
        logger.debug(f"[CERTSTREAM] Callback error: {e}")


def start_cert_monitor() -> bool:
    """
    Start the CertStream monitor in a background daemon thread.
    
    Returns:
        True if monitor started successfully, False otherwise
    """
    global _monitor_running, _monitor_thread
    
    if _monitor_running:
        logger.info("[CERTSTREAM] Monitor already running")
        return True
    
    try:
        logger.info("[CERTSTREAM] Starting Certificate Transparency monitor...")
        
        def _run_certstream():
            """Internal function to run CertStream listener"""
            global _monitor_running
            _monitor_running = True
            
            try:
                certstream.listen_for_events(
                    _certstream_callback,
                    url='wss://certstream.calidog.io/'
                )
            except Exception as e:
                logger.error(f"[CERTSTREAM] Monitor error: {e}")
            finally:
                _monitor_running = False
        
        # Start in daemon thread (won't block app shutdown)
        _monitor_thread = threading.Thread(
            target=_run_certstream,
            name="CertStreamMonitor",
            daemon=True
        )
        _monitor_thread.start()
        
        logger.info("[OK] CertStream monitor started in background thread")
        return True
        
    except Exception as e:
        logger.error(f"[CERTSTREAM] Failed to start monitor: {e}")
        return False


def stop_cert_monitor() -> None:
    """Stop the CertStream monitor (if running)"""
    global _monitor_running
    
    if _monitor_running:
        _monitor_running = False
        logger.info("[CERTSTREAM] Monitor stopped")


def check_realtime_threat(domain_or_url: str) -> bool:
    """
    Check if a domain exists in the real-time suspicious cache.
    
    This provides Zero-Day detection by catching domains that were
    registered very recently (within the app's uptime) and contain
    suspicious patterns.
    
    Args:
        domain_or_url: Domain name or full URL to check
        
    Returns:
        True if domain is in the suspicious cache (Zero-Day threat)
    """
    # Extract domain from URL if needed
    if '://' in domain_or_url:
        try:
            parsed = urlparse(domain_or_url)
            domain = parsed.netloc.lower()
        except Exception:
            domain = domain_or_url.lower()
    else:
        domain = domain_or_url.lower()
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    with _cache_lock:
        # Check exact match
        if domain in SUSPICIOUS_CACHE:
            logger.warning(f"[ZERO-DAY] Real-time threat detected: {domain}")
            return True
        
        # Check if domain is a subdomain of a cached suspicious domain
        for cached_domain in SUSPICIOUS_CACHE:
            if domain.endswith('.' + cached_domain):
                logger.warning(f"[ZERO-DAY] Subdomain of threat detected: {domain}")
                return True
    
    return False


def get_cache_stats() -> dict:
    """Get statistics about the suspicious domain cache"""
    with _cache_lock:
        return {
            "cache_size": len(SUSPICIOUS_CACHE),
            "max_size": CACHE_MAX_SIZE,
            "monitor_running": _monitor_running,
            "sample_domains": list(SUSPICIOUS_CACHE)[:10]  # First 10 for debugging
        }


# Export public functions
__all__ = [
    'start_cert_monitor',
    'stop_cert_monitor', 
    'check_realtime_threat',
    'get_cache_stats',
    'TARGET_KEYWORDS',
    'SUSPICIOUS_CACHE'
]
