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
Vision Scanner Service - Browser-based Forensic Analysis (STATELESS + STEALTH)

ARCHITECTURE:
- STATELESS: No request-specific data stored in class attributes
- Each scan creates its own browser context that is destroyed after use
- No shared browser state between concurrent requests (prevents race conditions)

STEALTH MODE:
- Uses playwright-stealth to bypass bot detection
- Randomized User-Agent headers
- Anti-automation flags disabled
- Graceful handling of Cloudflare 401/403 challenges
"""

import asyncio
import logging
import re
import random
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Check if Playwright is available
try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not installed. Vision Scanner will be disabled.")

# Check if playwright-stealth is available
try:
    from playwright_stealth import stealth_async
    STEALTH_AVAILABLE = True
except ImportError:
    STEALTH_AVAILABLE = False
    logger.warning("playwright-stealth not installed. Stealth mode will be limited.")


# ============================================================================
# STATIC CONFIGURATION (Safe to share across requests)
# ============================================================================

# Suspicious keywords to look for in hidden content
SUSPICIOUS_KEYWORDS = [
    'login', 'password', 'verify', 'account', 'signin', 'credential',
    'bank', 'paypal', 'credit', 'ssn', 'social security', 'update',
    'confirm', 'suspend', 'locked', 'urgent', 'immediately'
]

# Known tracker domains (partial list)
KNOWN_TRACKERS = {
    'google-analytics.com', 'googletagmanager.com', 'facebook.net',
    'doubleclick.net', 'analytics.', 'tracking.', 'pixel.', 'beacon.'
}

# User-Agent rotation pool for stealth
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# Browser launch args for stealth
STEALTH_BROWSER_ARGS = [
    "--disable-blink-features=AutomationControlled",  # Hide automation flag
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-software-rasterizer",
    "--disable-infobars",
    "--disable-notifications",
    "--disable-popup-blocking",
    "--disable-translate",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--window-size=1920,1080",
]

# Domains to ignore 401/403 errors from (Cloudflare challenges)
BOT_CHECK_DOMAINS = [
    'challenges.cloudflare.com',
    'cloudflare.com',
    'turnstile',
    'captcha',
    'hcaptcha.com',
    'recaptcha.net',
    'gstatic.com/recaptcha',
]

# Default timeout
PAGE_TIMEOUT = 30000  # 30 seconds


# ============================================================================
# STATELESS DETECTION FUNCTIONS
# ============================================================================

async def detect_evasion_techniques(page: Page) -> Dict[str, Any]:
    """
    Detect hidden content and evasion techniques on a page.
    STATELESS: Takes page as input, returns result dict.
    
    Args:
        page: Playwright Page object
        
    Returns:
        Dict with evasion_detected flag and hidden_threats list
    """
    result = {
        'evasion_detected': False,
        'hidden_threats': [],
        'right_click_disabled': False,
        'details': {}
    }
    
    try:
        # JavaScript to detect hidden elements with suspicious content
        hidden_elements_script = """
        () => {
            const suspiciousKeywords = %s;
            const hiddenThreats = [];
            
            // Get all elements
            const allElements = document.querySelectorAll('*');
            
            for (const el of allElements) {
                const style = window.getComputedStyle(el);
                const text = (el.textContent || el.innerText || '').toLowerCase().trim();
                
                // Skip empty elements
                if (!text) continue;
                
                // Check if element is hidden
                const isHidden = (
                    style.display === 'none' ||
                    style.visibility === 'hidden' ||
                    parseFloat(style.opacity) === 0 ||
                    (el.getBoundingClientRect().left < -9000) ||
                    (el.getBoundingClientRect().top < -9000) ||
                    (parseInt(style.left) < -9000) ||
                    (parseInt(style.top) < -9000) ||
                    (parseInt(style.width) === 0 && parseInt(style.height) === 0)
                );
                
                if (isHidden) {
                    // Check if contains suspicious keywords
                    for (const keyword of suspiciousKeywords) {
                        if (text.includes(keyword.toLowerCase())) {
                            hiddenThreats.push({
                                tag: el.tagName,
                                keyword: keyword,
                                text: text.substring(0, 100),
                                hiddenBy: style.display === 'none' ? 'display:none' :
                                          style.visibility === 'hidden' ? 'visibility:hidden' :
                                          parseFloat(style.opacity) === 0 ? 'opacity:0' : 'off-screen'
                            });
                            break;  // One match per element is enough
                        }
                    }
                }
            }
            
            return hiddenThreats;
        }
        """ % str(SUSPICIOUS_KEYWORDS)
        
        hidden_threats = await page.evaluate(hidden_elements_script)
        
        if hidden_threats:
            result['evasion_detected'] = True
            result['hidden_threats'] = hidden_threats
            logger.warning(f"[VisionScanner] Found {len(hidden_threats)} hidden threats")
        
        # Check for right-click disabling
        right_click_script = """
        () => {
            let rightClickDisabled = false;
            
            if (document.body && document.body.oncontextmenu) {
                rightClickDisabled = true;
            }
            
            const bodyHTML = document.body ? document.body.outerHTML : '';
            if (bodyHTML.includes('oncontextmenu') && 
                (bodyHTML.includes('return false') || bodyHTML.includes('preventDefault'))) {
                rightClickDisabled = true;
            }
            
            const scripts = document.querySelectorAll('script');
            for (const script of scripts) {
                const content = script.textContent || '';
                if (content.includes('contextmenu') && 
                    (content.includes('preventDefault') || content.includes('return false'))) {
                    rightClickDisabled = true;
                    break;
                }
            }
            
            return rightClickDisabled;
        }
        """
        
        right_click_disabled = await page.evaluate(right_click_script)
        result['right_click_disabled'] = right_click_disabled
        
        if right_click_disabled:
            result['evasion_detected'] = True
            logger.warning("[VisionScanner] Right-click disabled - potential evasion")
            
        # Additional check: Detect invisible iframes
        iframe_script = """
        () => {
            const iframes = document.querySelectorAll('iframe');
            const suspiciousIframes = [];
            
            for (const iframe of iframes) {
                const style = window.getComputedStyle(iframe);
                const rect = iframe.getBoundingClientRect();
                
                if (rect.width <= 1 || rect.height <= 1 ||
                    style.display === 'none' || 
                    parseFloat(style.opacity) === 0) {
                    suspiciousIframes.push({
                        src: iframe.src || 'no-src',
                        width: rect.width,
                        height: rect.height,
                        hidden: true
                    });
                }
            }
            
            return suspiciousIframes;
        }
        """
        
        suspicious_iframes = await page.evaluate(iframe_script)
        if suspicious_iframes:
            result['evasion_detected'] = True
            result['details']['hidden_iframes'] = suspicious_iframes
            logger.warning(f"[VisionScanner] Found {len(suspicious_iframes)} hidden iframes")
            
    except Exception as e:
        logger.error(f"[VisionScanner] Evasion detection error: {e}")
        result['details']['error'] = str(e)[:200]
        
    return result


async def full_scan(url: str) -> Dict[str, Any]:
    """
    Perform a complete vision scan with STEALTH MODE.
    
    STATELESS DESIGN:
    - Creates a new browser context for each scan
    - No shared state between concurrent requests
    - Browser context is destroyed after scan
    
    STEALTH FEATURES:
    - Randomized User-Agent
    - playwright-stealth injection
    - Anti-automation flags disabled
    - Graceful 401/403 handling for Cloudflare
    
    Args:
        url: URL to scan
        
    Returns:
        Complete scan results
    """
    # Safe Failure response structure
    result = {
        'url': url,
        'evasion': None,
        'connections': None,
        'screenshot_path': None,
        'error': None,
        'bot_check_triggered': False
    }
    
    if not PLAYWRIGHT_AVAILABLE:
        result['error'] = 'Playwright not installed'
        return result
    
    # Request-local state (no class attributes!)
    external_domains: Set[str] = set()
    suspicious_ips: Set[str] = set()
    trackers: Set[str] = set()
    total_requests = 0
    bot_check_triggered = False
    
    # Parse main domain for comparison
    main_parsed = urlparse(url)
    main_domain = main_parsed.netloc.lower()
    if ':' in main_domain:
        main_domain = main_domain.split(':')[0]
    main_parts = main_domain.split('.')
    main_root = '.'.join(main_parts[-2:]) if len(main_parts) >= 2 else main_domain
    
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    
    playwright = None
    browser = None
    context = None
    page = None
    
    try:
        # ============================================================
        # STATELESS: Create new browser instance for this request
        # ============================================================
        playwright = await async_playwright().start()
        
        # Launch with stealth args
        browser = await playwright.chromium.launch(
            headless=True,
            args=STEALTH_BROWSER_ARGS
        )
        
        # Create new context with randomized User-Agent
        context = await browser.new_context(
            user_agent=random.choice(USER_AGENTS),
            viewport={'width': 1920, 'height': 1080},
            locale='en-US',
            timezone_id='America/New_York'
        )
        
        page = await context.new_page()
        
        # ============================================================
        # STEALTH: Apply playwright-stealth if available
        # ============================================================
        if STEALTH_AVAILABLE:
            await stealth_async(page)
            logger.debug("[VisionScanner] Stealth mode applied")
        
        # ============================================================
        # REQUEST HANDLER with 401/403 tolerance
        # ============================================================
        def request_handler(request):
            nonlocal external_domains, suspicious_ips, trackers, total_requests
            try:
                req_url = request.url
                parsed = urlparse(req_url)
                req_domain = parsed.netloc.lower()
                if ':' in req_domain:
                    req_domain = req_domain.split(':')[0]
                if not req_domain:
                    return
                total_requests += 1
                
                if ip_pattern.match(req_domain):
                    suspicious_ips.add(req_domain)
                    return
                
                req_parts = req_domain.split('.')
                req_root = '.'.join(req_parts[-2:]) if len(req_parts) >= 2 else req_domain
                
                if req_root != main_root:
                    external_domains.add(req_domain)
                    for tracker in KNOWN_TRACKERS:
                        if tracker in req_domain:
                            trackers.add(req_domain)
                            break
            except Exception:
                pass
        
        def response_handler(response):
            """Handle responses - gracefully ignore Cloudflare 401/403"""
            nonlocal bot_check_triggered
            try:
                if response.status in [401, 403]:
                    req_url = response.url
                    # Check if this is a bot check domain
                    for bot_domain in BOT_CHECK_DOMAINS:
                        if bot_domain in req_url:
                            bot_check_triggered = True
                            logger.warning(f"[VisionScanner] Bot check triggered (ignored): {req_url[:80]}")
                            return
                    # Non-bot 401/403 - log but don't fail
                    logger.debug(f"[VisionScanner] {response.status} on {req_url[:60]}")
            except Exception:
                pass
        
        page.on("request", request_handler)
        page.on("response", response_handler)
        
        # ============================================================
        # NAVIGATE with timeout tolerance
        # ============================================================
        try:
            await page.goto(url, timeout=PAGE_TIMEOUT, wait_until='networkidle')
        except Exception as nav_error:
            # Page may still have loaded partially - continue analysis
            logger.warning(f"[VisionScanner] Navigation warning (continuing): {str(nav_error)[:100]}")
        
        # Wait for dynamic content
        await asyncio.sleep(2)
        
        # ============================================================
        # DETECT EVASION TECHNIQUES
        # ============================================================
        evasion_result = await detect_evasion_techniques(page)
        result['evasion'] = evasion_result
        
        # ============================================================
        # COMPILE CONNECTION RESULTS
        # ============================================================
        result['connections'] = {
            'external_domains': sorted(list(external_domains)),
            'suspicious_ips': sorted(list(suspicious_ips)),
            'trackers': sorted(list(trackers)),
            'total_requests': total_requests,
            'cross_origin_count': len(external_domains)
        }
        
        result['bot_check_triggered'] = bot_check_triggered
        
        logger.info(f"[VisionScanner] Scan complete: {len(external_domains)} external domains, "
                   f"evasion_detected={evasion_result['evasion_detected']}, "
                   f"bot_check={bot_check_triggered}")
        
    except Exception as e:
        logger.error(f"[VisionScanner] Full scan error: {e}")
        result['error'] = str(e)[:200]
        
    finally:
        # ============================================================
        # CLEANUP: Destroy all browser resources (stateless!)
        # ============================================================
        try:
            if page:
                await page.close()
        except Exception:
            pass
        try:
            if context:
                await context.close()
        except Exception:
            pass
        try:
            if browser:
                await browser.close()
        except Exception:
            pass
        try:
            if playwright:
                await playwright.stop()
        except Exception:
            pass
                    
    return result


# ============================================================================
# PUBLIC API (Stateless functions)
# ============================================================================

async def scan_url_vision(url: str) -> Dict[str, Any]:
    """
    Convenience async function for vision scanning.
    STATELESS: Creates new browser per request, no shared state.
    
    Args:
        url: URL to scan
        
    Returns:
        Vision scan results
    """
    return await full_scan(url)


def is_vision_scanner_available() -> bool:
    """Check if vision scanner is available"""
    return PLAYWRIGHT_AVAILABLE
