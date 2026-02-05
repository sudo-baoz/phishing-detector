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
Vision Scanner Service - Browser-based Forensic Analysis
Uses Playwright for:
1. Hidden Content & Evasion Detection
2. External Connection/Tracker Tracing
3. Visual Screenshot Capture
"""

import asyncio
import logging
import re
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Check if Playwright is available
try:
    from playwright.async_api import async_playwright, Page, Browser
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not installed. Vision Scanner will be disabled.")


class VisionScanner:
    """
    Browser-based forensic scanner using Playwright.
    Detects evasion techniques and tracks external connections.
    """
    
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
    
    def __init__(self):
        self.browser: Optional[Browser] = None
        self.timeout = 30000  # 30 seconds page load timeout
        
    async def _ensure_browser(self) -> Browser:
        """Ensure browser instance is available"""
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright is not installed")
            
        if self.browser is None:
            playwright = await async_playwright().start()
            self.browser = await playwright.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-extensions'
                ]
            )
        return self.browser
    
    async def close(self):
        """Close browser instance"""
        if self.browser:
            await self.browser.close()
            self.browser = None
            
    async def detect_evasion_techniques(self, page: Page) -> Dict[str, Any]:
        """
        Detect hidden content and evasion techniques on a page.
        
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
            """ % str(self.SUSPICIOUS_KEYWORDS)
            
            hidden_threats = await page.evaluate(hidden_elements_script)
            
            if hidden_threats:
                result['evasion_detected'] = True
                result['hidden_threats'] = hidden_threats
                logger.warning(f"[VisionScanner] Found {len(hidden_threats)} hidden threats")
            
            # Check for right-click disabling
            right_click_script = """
            () => {
                // Check if contextmenu event is being prevented
                let rightClickDisabled = false;
                
                // Check for oncontextmenu attribute on body or document
                if (document.body && document.body.oncontextmenu) {
                    rightClickDisabled = true;
                }
                
                // Check for event listeners (limited detection)
                const bodyHTML = document.body ? document.body.outerHTML : '';
                if (bodyHTML.includes('oncontextmenu') && 
                    (bodyHTML.includes('return false') || bodyHTML.includes('preventDefault'))) {
                    rightClickDisabled = true;
                }
                
                // Check script content
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
                    
                    // Check for tiny/hidden iframes
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
    
    async def trace_external_connections(
        self, 
        url: str, 
        page: Optional[Page] = None
    ) -> Dict[str, Any]:
        """
        Trace all external network connections made during page load.
        
        Args:
            url: URL to scan
            page: Optional existing page object
            
        Returns:
            Dict with external_domains, suspicious_ips, and trackers
        """
        result = {
            'external_domains': [],
            'suspicious_ips': [],
            'trackers': [],
            'total_requests': 0,
            'cross_origin_count': 0
        }
        
        # Parse the main domain for comparison
        main_parsed = urlparse(url)
        main_domain = main_parsed.netloc.lower()
        if ':' in main_domain:
            main_domain = main_domain.split(':')[0]
        
        # Extract root domain (e.g., example.com from sub.example.com)
        main_parts = main_domain.split('.')
        main_root = '.'.join(main_parts[-2:]) if len(main_parts) >= 2 else main_domain
        
        external_domains: Set[str] = set()
        suspicious_ips: Set[str] = set()
        trackers: Set[str] = set()
        
        # IP address pattern
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        
        def request_handler(request):
            """Handle each network request"""
            nonlocal external_domains, suspicious_ips, trackers
            
            try:
                req_url = request.url
                parsed = urlparse(req_url)
                req_domain = parsed.netloc.lower()
                
                if ':' in req_domain:
                    req_domain = req_domain.split(':')[0]
                
                if not req_domain:
                    return
                    
                result['total_requests'] += 1
                
                # Check if it's an IP address
                if ip_pattern.match(req_domain):
                    suspicious_ips.add(req_domain)
                    logger.warning(f"[VisionScanner] Suspicious IP connection: {req_domain}")
                    return
                
                # Check if it's cross-origin
                req_parts = req_domain.split('.')
                req_root = '.'.join(req_parts[-2:]) if len(req_parts) >= 2 else req_domain
                
                if req_root != main_root:
                    external_domains.add(req_domain)
                    result['cross_origin_count'] += 1
                    
                    # Check if it's a known tracker
                    for tracker in self.KNOWN_TRACKERS:
                        if tracker in req_domain:
                            trackers.add(req_domain)
                            break
                            
            except Exception as e:
                logger.debug(f"[VisionScanner] Request handler error: {e}")
        
        try:
            if page is None:
                browser = await self._ensure_browser()
                page = await browser.new_page()
                should_close_page = True
            else:
                should_close_page = False
            
            # Attach request handler
            page.on("request", request_handler)
            
            # Navigate to the page
            await page.goto(url, timeout=self.timeout, wait_until='networkidle')
            
            # Wait a bit for any lazy-loaded resources
            await asyncio.sleep(2)
            
            # Convert sets to lists
            result['external_domains'] = sorted(list(external_domains))
            result['suspicious_ips'] = sorted(list(suspicious_ips))
            result['trackers'] = sorted(list(trackers))
            
            if should_close_page:
                await page.close()
                
        except Exception as e:
            logger.error(f"[VisionScanner] Connection tracing error: {e}")
            result['error'] = str(e)[:200]
            
        return result
    
    async def full_scan(self, url: str) -> Dict[str, Any]:
        """
        Perform a complete vision scan including:
        - Evasion detection
        - External connection tracing
        - Screenshot capture (optional)
        
        Args:
            url: URL to scan
            
        Returns:
            Complete scan results
        """
        result = {
            'url': url,
            'evasion': None,
            'connections': None,
            'screenshot_path': None,
            'error': None
        }
        
        if not PLAYWRIGHT_AVAILABLE:
            result['error'] = 'Playwright not installed'
            return result
            
        page = None
        
        try:
            browser = await self._ensure_browser()
            page = await browser.new_page()
            
            # Set up request interception before navigation
            external_domains: Set[str] = set()
            suspicious_ips: Set[str] = set()
            trackers: Set[str] = set()
            total_requests = 0
            
            main_parsed = urlparse(url)
            main_domain = main_parsed.netloc.lower()
            if ':' in main_domain:
                main_domain = main_domain.split(':')[0]
            main_parts = main_domain.split('.')
            main_root = '.'.join(main_parts[-2:]) if len(main_parts) >= 2 else main_domain
            
            ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
            
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
                        for tracker in self.KNOWN_TRACKERS:
                            if tracker in req_domain:
                                trackers.add(req_domain)
                                break
                except Exception:
                    pass
            
            page.on("request", request_handler)
            
            # Navigate
            await page.goto(url, timeout=self.timeout, wait_until='networkidle')
            
            # Wait for dynamic content
            await asyncio.sleep(2)
            
            # Detect evasion techniques
            evasion_result = await self.detect_evasion_techniques(page)
            result['evasion'] = evasion_result
            
            # Compile connection results
            result['connections'] = {
                'external_domains': sorted(list(external_domains)),
                'suspicious_ips': sorted(list(suspicious_ips)),
                'trackers': sorted(list(trackers)),
                'total_requests': total_requests,
                'cross_origin_count': len(external_domains)
            }
            
            logger.info(f"[VisionScanner] Scan complete: {len(external_domains)} external domains, "
                       f"evasion_detected={evasion_result['evasion_detected']}")
            
        except Exception as e:
            logger.error(f"[VisionScanner] Full scan error: {e}")
            result['error'] = str(e)[:200]
            
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
                    
        return result


# Singleton instance
vision_scanner = VisionScanner()


async def scan_url_vision(url: str) -> Dict[str, Any]:
    """
    Convenience async function for vision scanning.
    
    Args:
        url: URL to scan
        
    Returns:
        Vision scan results
    """
    return await vision_scanner.full_scan(url)


def is_vision_scanner_available() -> bool:
    """Check if vision scanner is available"""
    return PLAYWRIGHT_AVAILABLE
