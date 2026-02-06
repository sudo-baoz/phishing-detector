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
import base64
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

# App config (proxy settings)
try:
    from app.config import settings
except ImportError:
    settings = None

# Captcha solver (Strategy Pattern)
try:
    from app.services.captcha_manager import CaptchaFactory
    CAPTCHA_AVAILABLE = True
except ImportError:
    CAPTCHA_AVAILABLE = False
    CaptchaFactory = None

# Network traffic analyzer (XHR/Fetch exfiltration)
try:
    from app.services.network_forensics import NetworkAnalyzer
    NETWORK_ANALYZER_AVAILABLE = True
except ImportError:
    NETWORK_ANALYZER_AVAILABLE = False
    NetworkAnalyzer = None


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

# Soft-block (Cloudflare / captcha) detection keywords in title or body
SOFT_BLOCK_TITLE_KEYWORDS = [
    "just a moment",
    "verify you are human",
    "security check",
    "attention required",
    "checking your browser",
    "ddos protection",
    "please wait",
]
SOFT_BLOCK_BODY_MARKERS = [
    "challenges.cloudflare.com",
    "cf-browser-verification",
    "turnstile",
    "g-recaptcha",
    "recaptcha/api",
]
# Bypass attempt: give up after this many seconds and snapshot whatever is there
SOFT_BLOCK_BYPASS_TIMEOUT = 10


# ============================================================================
# PROXY CONFIGURATION (Residential proxy to bypass Cloudflare IP blocks)
# ============================================================================

def _get_proxy_config() -> Optional[Dict[str, str]]:
    """Build Playwright proxy dict from settings. Returns None if proxy not configured."""
    if not settings:
        return None
    server = (settings.PROXY_SERVER or "").strip()
    if not server:
        return None
    proxy_config: Dict[str, str] = {"server": server}
    username = (settings.PROXY_USERNAME or "").strip()
    password = (settings.PROXY_PASSWORD or "").strip()
    if username and password:
        proxy_config["username"] = username
        proxy_config["password"] = password
    return proxy_config


def _is_proxy_related_error(exc: BaseException) -> bool:
    """True if the exception is likely due to proxy failure (timeout, connection refused)."""
    msg = (getattr(exc, "message", "") or str(exc)).lower()
    if "timeout" in msg or "timed out" in msg:
        return True
    if "proxy" in msg or "connection_refused" in msg or "connection refused" in msg:
        return True
    if "err_proxy" in msg or "net::err_" in msg:
        return True
    return False


# ============================================================================
# SOFT-BLOCK BYPASS (Smart Wait & Click)
# ============================================================================

async def _is_soft_block_page(page: Page) -> bool:
    """Return True if the current page looks like a Cloudflare/captcha verification screen."""
    try:
        title = (await page.title() or "").lower()
        for kw in SOFT_BLOCK_TITLE_KEYWORDS:
            if kw in title:
                return True
        content = await page.content()
        for marker in SOFT_BLOCK_BODY_MARKERS:
            if marker in content:
                return True
    except Exception:
        pass
    return False


async def _try_bypass_cloudflare_click(page: Page) -> bool:
    """
    Attempt to bypass a Cloudflare / Turnstile "soft block" by waiting for the
    challenge iframe, hovering, random delay, and clicking the checkbox.
    Returns True if we believe the challenge was passed (e.g. redirect or content changed).
    """
    try:
        # Wait for Cloudflare challenge iframe
        frame_el = await page.wait_for_selector(
            "iframe[src*='challenges.cloudflare.com'], iframe[src*='challenges'], #turnstile-wrapper iframe",
            timeout=5000,
        )
        if not frame_el:
            return False
        frame = await frame_el.content_frame()
        if not frame:
            return False
        # Find clickable area (checkbox or label inside the challenge frame)
        checkbox = await frame.wait_for_selector(
            "input[type='checkbox'], .ctp-checkbox-label, .mark, body",
            timeout=3000,
        )
        if not checkbox:
            return False
        await checkbox.hover()
        delay_ms = random.randint(500, 1500)
        await page.wait_for_timeout(delay_ms)
        await checkbox.click()
        logger.info("[VisionScanner] Clicked Cloudflare widget. Waiting for reload...")
        await page.wait_for_load_state("networkidle", timeout=8000)
        return True
    except Exception as e:
        logger.debug(f"[VisionScanner] Inline bypass attempt failed: {e}")
        return False


async def _try_bypass_soft_block(page: Page, url: str) -> bool:
    """
    If the page looks like a soft-block (Cloudflare/captcha), try the smart
    wait & click bypass. Total time limited by SOFT_BLOCK_BYPASS_TIMEOUT.
    Returns True if bypass succeeded or no soft-block detected; False on timeout/failure.
    """
    if not await _is_soft_block_page(page):
        return True
    logger.warning(f"🚧 Cloaking detected on {url}. Attempting bypass...")
    try:
        await asyncio.wait_for(
            _try_bypass_cloudflare_click(page),
            timeout=SOFT_BLOCK_BYPASS_TIMEOUT,
        )
        logger.info("✅ Bypass completed (or page updated).")
        return True
    except asyncio.TimeoutError:
        logger.warning(f"⚠️ Bypass timed out after {SOFT_BLOCK_BYPASS_TIMEOUT}s. Snapshotting current page.")
        return False
    except Exception as e:
        logger.warning(f"⚠️ Bypass failed: {e}. Snapshotting current page.")
        return False


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


# ============================================================================
# DUAL DEVICE FULL-PAGE SCREENSHOTS (Desktop + Mobile)
# ============================================================================

async def _capture_single_device(
    browser: Any,
    playwright: Any,
    url: str,
    device_config: Dict[str, Any],
    context_name: str,
) -> Optional[str]:
    """
    Capture a full-page JPEG screenshot for one device (desktop viewport or mobile preset).
    Returns data URI string or None on failure.
    """
    context = None
    try:
        logger.debug("[VisionScanner] Starting capture for: %s", context_name)
        if device_config.get("device_descriptor") and playwright:
            device = playwright.devices.get(device_config["device_descriptor"])
            if device:
                context = await browser.new_context(**device)
            else:
                context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        else:
            viewport = device_config.get("viewport", {"width": 1920, "height": 1080})
            context = await browser.new_context(viewport=viewport)
        page = await context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
            await page.wait_for_timeout(2000)
            screenshot_bytes = await page.screenshot(full_page=True, type="jpeg", quality=70)
            b64_img = base64.b64encode(screenshot_bytes).decode("utf-8")
            return f"data:image/jpeg;base64,{b64_img}"
        finally:
            await page.close()
    except Exception as e:
        logger.warning("[VisionScanner] Capture failed for %s: %s", context_name, e)
        return None
    finally:
        if context:
            try:
                await context.close()
            except Exception:
                pass


async def _capture_dual_screenshots(
    browser: Any,
    playwright: Any,
    url: str,
) -> Dict[str, Optional[str]]:
    """Run desktop and mobile full-page captures in parallel. Returns { desktop_b64, mobile_b64 }."""
    desktop_config = {"viewport": {"width": 1920, "height": 1080}}
    mobile_config = {"device_descriptor": "iPhone 13 Pro"}
    desktop_task = _capture_single_device(browser, playwright, url, desktop_config, "Desktop")
    mobile_task = _capture_single_device(browser, playwright, url, mobile_config, "Mobile")
    desktop_b64, mobile_b64 = await asyncio.gather(desktop_task, mobile_task)
    return {"desktop_b64": desktop_b64, "mobile_b64": mobile_b64}


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
        'network_logs': [],
        'network_analysis': None,
        'screenshot_path': None,
        'desktop_b64': None,
        'mobile_b64': None,
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
    network_logs: List[Dict[str, Any]] = []  # XHR/Fetch capture for exfiltration analysis
    
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
        try:
            playwright = await async_playwright().start()
            
            # Launch with stealth args
            browser = await playwright.chromium.launch(
                headless=True,
                args=STEALTH_BROWSER_ARGS
            )
        except Exception as launch_error:
            # Browser launch failed (missing dependencies, etc.)
            # Return graceful fallback instead of crashing
            logger.error(f"[VisionScanner] Browser launch failed: {launch_error}")
            result['error'] = f"Browser unavailable: {str(launch_error)[:100]}"
            result['evasion'] = {'evasion_detected': False, 'hidden_threats': [], 'details': {'error': 'browser_unavailable'}}
            result['connections'] = {'external_domains': [], 'suspicious_ips': [], 'trackers': [], 'total_requests': 0, 'cross_origin_count': 0}
            return result
        
        proxy_config = _get_proxy_config()
        if proxy_config:
            logger.debug(f"[VisionScanner] Using proxy: {proxy_config.get('server', '')[:60]}")

        # Create new context with randomized User-Agent and optional proxy
        context = await browser.new_context(
            user_agent=random.choice(USER_AGENTS),
            viewport={'width': 1920, 'height': 1080},
            locale='en-US',
            timezone_id='America/New_York',
            proxy=proxy_config,
        )
        
        page = await context.new_page()
        
        # ============================================================
        # STEALTH: Apply playwright-stealth if available
        # ============================================================
        if STEALTH_AVAILABLE:
            await stealth_async(page)
            logger.debug("[VisionScanner] Stealth mode applied")
        
        # ============================================================
        # REQUEST HANDLER: connections + XHR/Fetch capture for exfiltration
        # ============================================================
        def request_handler(request):
            nonlocal external_domains, suspicious_ips, trackers, total_requests, network_logs
            try:
                req_url = request.url
                parsed = urlparse(req_url)
                req_domain = parsed.netloc.lower()
                if ':' in req_domain:
                    req_domain = req_domain.split(':')[0]
                if not req_domain:
                    return
                total_requests += 1

                # Capture XHR/Fetch for exfiltration analysis (URL, method, post_data)
                try:
                    res_type = getattr(request, "resource_type", None) or ""
                    if res_type in ("xhr", "fetch"):
                        post_data = getattr(request, "post_data", None)
                        network_logs.append({
                            "url": req_url,
                            "method": (getattr(request, "method", None) or "GET").upper(),
                            "post_data": post_data[:2000] if post_data else None,
                        })
                except Exception:
                    pass

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
        # NAVIGATE with timeout tolerance (proxy fallback on failure)
        # ============================================================
        nav_ok = False
        try:
            await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            nav_ok = True
        except Exception as nav_error:
            if proxy_config and _is_proxy_related_error(nav_error):
                logger.warning("⚠️ Proxy failed, retrying with direct connection...")
                try:
                    await page.close()
                except Exception:
                    pass
                try:
                    await context.close()
                except Exception:
                    pass
                context = await browser.new_context(
                    user_agent=random.choice(USER_AGENTS),
                    viewport={'width': 1920, 'height': 1080},
                    locale='en-US',
                    timezone_id='America/New_York',
                    proxy=None,
                )
                page = await context.new_page()
                if STEALTH_AVAILABLE:
                    await stealth_async(page)
                page.on("request", request_handler)
                page.on("response", response_handler)
                try:
                    await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    nav_ok = True
                except Exception as direct_error:
                    logger.warning(f"[VisionScanner] Direct connection also failed (continuing): {str(direct_error)[:100]}")
            else:
                logger.warning(f"[VisionScanner] Navigation warning (continuing): {str(nav_error)[:100]}")
        
        # Wait for dynamic content and challenge widgets to appear
        await asyncio.sleep(2)
        
        # ============================================================
        # SOFT-BLOCK BYPASS (Smart Wait & Click — Cloudflare / Turnstile)
        # ============================================================
        await _try_bypass_soft_block(page, url)
        
        # ============================================================
        # CAPTCHA BYPASS (Strategy Pattern: StealthClick / 2Captcha / CapSolver)
        # ============================================================
        if CAPTCHA_AVAILABLE and CaptchaFactory:
            try:
                # Detect captcha widget and optional sitekey
                captcha_info = await page.evaluate("""
                    () => {
                        const turnstile = document.querySelector('[data-sitekey]');
                        const recaptcha = document.querySelector('.g-recaptcha[data-sitekey], [data-sitekey]');
                        const sitekey = (turnstile || recaptcha)?.getAttribute('data-sitekey') || '';
                        const hasIframe = !!document.querySelector('iframe[src*="challenges.cloudflare.com"], iframe[src*="recaptcha"]');
                        return { sitekey, present: !!(turnstile || recaptcha || hasIframe) };
                    }
                """)
                if captcha_info.get("present") or bot_check_triggered:
                    solver = CaptchaFactory.get_solver()
                    sitekey = captcha_info.get("sitekey") or None
                    current_url = page.url or url
                    is_solved = await solver.solve(page, sitekey=sitekey, url=current_url)
                    if is_solved:
                        logger.info("✅ Captcha bypassed!")
                        await asyncio.sleep(1)
                    else:
                        logger.warning("❌ Failed to solve captcha.")
            except Exception as cap_err:
                logger.warning(f"[VisionScanner] Captcha solver error (continuing): {cap_err}")
        
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

        # ============================================================
        # NETWORK TRAFFIC (XHR/Fetch) + EXFILTRATION ANALYSIS
        # ============================================================
        result['network_logs'] = network_logs
        if NETWORK_ANALYZER_AVAILABLE and NetworkAnalyzer:
            try:
                result['network_analysis'] = NetworkAnalyzer.analyze_traffic(network_logs)
                if result['network_analysis'].get('exfiltration_detected'):
                    result['evasion'] = result['evasion'] or {}
                    if isinstance(result['evasion'], dict):
                        result['evasion']['evasion_detected'] = (
                            result['evasion'].get('evasion_detected', False) or True
                        )
                        result['evasion'].setdefault('details', {})['exfiltration_risk'] = (
                            result['network_analysis'].get('high_risk_findings', [])
                        )
            except Exception as na_err:
                logger.debug("[VisionScanner] Network analysis failed: %s", na_err)
                result['network_analysis'] = {
                    'high_risk_findings': [],
                    'total_captured': len(network_logs),
                    'post_requests': sum(1 for r in network_logs if (r.get('method') or '').upper() == 'POST'),
                    'exfiltration_detected': False,
                }
        else:
            result['network_analysis'] = {
                'high_risk_findings': [],
                'total_captured': len(network_logs),
                'post_requests': sum(1 for r in network_logs if (r.get('method') or '').upper() == 'POST'),
                'exfiltration_detected': False,
            }
        
        result['bot_check_triggered'] = bot_check_triggered
        
        logger.debug(f"[VisionScanner] Scan complete: {len(external_domains)} external domains, "
                   f"evasion_detected={evasion_result['evasion_detected']}, "
                   f"bot_check={bot_check_triggered}")

        # ============================================================
        # DUAL FULL-PAGE SCREENSHOTS (Desktop + Mobile, parallel)
        # ============================================================
        if browser and playwright:
            try:
                screenshots = await _capture_dual_screenshots(browser, playwright, url)
                result["desktop_b64"] = screenshots.get("desktop_b64")
                result["mobile_b64"] = screenshots.get("mobile_b64")
                logger.debug("[VisionScanner] Dual screenshots captured.")
            except Exception as cap_err:
                logger.warning("[VisionScanner] Dual screenshot capture failed: %s", cap_err)
        
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
