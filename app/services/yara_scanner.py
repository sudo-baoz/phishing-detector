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
YARA Scanner Service
Static analysis engine for detecting phishing kit markers, crypto wallets, and obfuscated code
"""

import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Check if yara-python is available
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python not installed. YARA Scanner will use fallback regex mode.")


class YaraScanner:
    """
    YARA-based static analysis scanner for detecting:
    - Cryptocurrency wallet addresses
    - Known phishing kit markers
    - Obfuscated JavaScript packers
    - Credential harvesting indicators
    """
    
    # YARA Rules as string (compiled at runtime)
    YARA_RULES_SOURCE = r'''
rule CryptoWallet_Bitcoin {
    meta:
        description = "Detects Bitcoin wallet addresses"
        author = "PhishingDetector"
        severity = "medium"
        category = "crypto"
    strings:
        // Legacy Bitcoin addresses (P2PKH - start with 1)
        $btc_legacy = /\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b/
        // SegWit Bitcoin addresses (P2SH - start with 3)
        $btc_segwit = /\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b/
        // Native SegWit (Bech32 - start with bc1)
        $btc_bech32 = /\bbc1[a-z0-9]{39,59}\b/
    condition:
        any of them
}

rule CryptoWallet_Ethereum {
    meta:
        description = "Detects Ethereum wallet addresses"
        author = "PhishingDetector"
        severity = "medium"
        category = "crypto"
    strings:
        $eth_address = /\b0x[a-fA-F0-9]{40}\b/
    condition:
        $eth_address
}

rule CryptoWallet_Monero {
    meta:
        description = "Detects Monero wallet addresses"
        author = "PhishingDetector"
        severity = "medium"
        category = "crypto"
    strings:
        $xmr_address = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/
    condition:
        $xmr_address
}

rule PhishingKit_16Shop {
    meta:
        description = "Detects 16Shop phishing kit markers"
        author = "PhishingDetector"
        severity = "critical"
        category = "phishing_kit"
    strings:
        $marker1 = "16shop" nocase
        $marker2 = "16-shop" nocase
        $marker3 = "sixteenshop" nocase
        $signature1 = "16shop_antibot"
        $signature2 = "/antibot/16"
    condition:
        any of them
}

rule PhishingKit_Z118 {
    meta:
        description = "Detects z118 phishing kit markers"
        author = "PhishingDetector"
        severity = "critical"
        category = "phishing_kit"
    strings:
        $marker1 = "z118" nocase
        $marker2 = "z-118" nocase
        $marker3 = "/z118/"
    condition:
        any of them
}

rule PhishingKit_KrGhost {
    meta:
        description = "Detects Kr3pto/Ghost phishing kit markers"
        author = "PhishingDetector"
        severity = "critical"
        category = "phishing_kit"
    strings:
        $kr3pto = "kr3pto" nocase
        $ghost = "ghostphish" nocase
        $chalbhai = "chalbhai" nocase
        $exo = "ex-robotos" nocase
    condition:
        any of them
}

rule PhishingKit_Uadmin {
    meta:
        description = "Detects U-Admin phishing panel"
        author = "PhishingDetector"
        severity = "critical"
        category = "phishing_kit"
    strings:
        $uadmin1 = "uadmin" nocase
        $uadmin2 = "u-admin" nocase
        $panel = "/uadmin/panel"
    condition:
        any of them
}

rule Obfuscation_JSPacker {
    meta:
        description = "Detects Dean Edwards JavaScript Packer"
        author = "PhishingDetector"
        severity = "high"
        category = "obfuscation"
    strings:
        $packer = /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/
    condition:
        $packer
}

rule Obfuscation_Base64Eval {
    meta:
        description = "Detects Base64 encoded eval execution"
        author = "PhishingDetector"
        severity = "high"
        category = "obfuscation"
    strings:
        $b64_eval = /eval\s*\(\s*atob\s*\(/
        $b64_decode = /atob\s*\(['""][A-Za-z0-9+\/=]{50,}['"]\)/
    condition:
        any of them
}

rule Obfuscation_HexEncoding {
    meta:
        description = "Detects heavy hex-encoded JavaScript"
        author = "PhishingDetector"
        severity = "medium"
        category = "obfuscation"
    strings:
        $hex_pattern = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/
    condition:
        #hex_pattern > 5
}

rule CredentialHarvester_FormAction {
    meta:
        description = "Detects suspicious form actions to external domains"
        author = "PhishingDetector"
        severity = "high"
        category = "credential_theft"
    strings:
        $telegram_bot = /api\.telegram\.org\/bot[0-9]+:[A-Za-z0-9_-]+/
        $discord_webhook = /discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/
        $external_post = /action\s*=\s*["']https?:\/\/[^"']+["']/
    condition:
        any of them
}

rule CredentialHarvester_InputFields {
    meta:
        description = "Detects password and sensitive input fields"
        author = "PhishingDetector"
        severity = "low"
        category = "credential_theft"
    strings:
        $password_input = /<input[^>]+type\s*=\s*["']password["']/i
        $ssn_field = /name\s*=\s*["']ssn["']/i
        $card_field = /name\s*=\s*["'](card|cc|creditcard|cvv|cvc)["']/i
    condition:
        any of them
}

rule Antibot_Detection {
    meta:
        description = "Detects anti-bot/anti-analysis techniques"
        author = "PhishingDetector"
        severity = "medium"
        category = "evasion"
    strings:
        $antibot1 = "navigator.webdriver" nocase
        $antibot2 = "phantom" nocase
        $antibot3 = "selenium" nocase
        $antibot4 = "headless" nocase
        $antibot5 = "puppeteer" nocase
        $devtools = "devtools" nocase
    condition:
        2 of them
}
'''
    
    def __init__(self):
        self.compiled_rules = None
        self._compile_rules()
        
    def _compile_rules(self):
        """Compile YARA rules from source"""
        if not YARA_AVAILABLE:
            logger.warning("[YaraScanner] YARA not available, using fallback mode")
            return
            
        try:
            self.compiled_rules = yara.compile(source=self.YARA_RULES_SOURCE)
            logger.info("[YaraScanner] YARA rules compiled successfully")
        except yara.SyntaxError as e:
            logger.error(f"[YaraScanner] YARA syntax error: {e}")
            self.compiled_rules = None
        except Exception as e:
            logger.error(f"[YaraScanner] Failed to compile YARA rules: {e}")
            self.compiled_rules = None
    
    def _fallback_scan(self, content: str) -> List[Dict[str, Any]]:
        """
        Fallback regex-based scanning when YARA is not available.
        """
        matches = []
        
        # Crypto wallet patterns
        patterns = {
            'CryptoWallet_Bitcoin': [
                r'\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b',
                r'\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b',
                r'\bbc1[a-z0-9]{39,59}\b'
            ],
            'CryptoWallet_Ethereum': [
                r'\b0x[a-fA-F0-9]{40}\b'
            ],
            'PhishingKit_16Shop': [
                r'16shop',
                r'16-shop'
            ],
            'PhishingKit_Z118': [
                r'z118',
                r'/z118/'
            ],
            'Obfuscation_JSPacker': [
                r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)'
            ],
            'CredentialHarvester_TelegramBot': [
                r'api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+'
            ],
            'CredentialHarvester_DiscordWebhook': [
                r'discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
            ]
        }
        
        content_lower = content.lower()
        
        for rule_name, rule_patterns in patterns.items():
            for pattern in rule_patterns:
                try:
                    if re.search(pattern, content, re.IGNORECASE):
                        matches.append({
                            'rule': rule_name,
                            'category': rule_name.split('_')[0].lower(),
                            'severity': 'high' if 'PhishingKit' in rule_name else 'medium',
                            'matched_data': None,  # Regex doesn't capture matched strings easily
                            'fallback_mode': True
                        })
                        break  # One match per rule is enough
                except re.error:
                    continue
        
        return matches
    
    def scan_content(self, content: str) -> Dict[str, Any]:
        """
        Scan HTML/text content for malicious patterns using YARA rules.
        
        Args:
            content: HTML or text content to scan
            
        Returns:
            Dict with matches, categories, and severity
        """
        result = {
            'matches': [],
            'triggered_rules': [],
            'categories': set(),
            'highest_severity': 'none',
            'total_matches': 0,
            'yara_available': YARA_AVAILABLE,
            'error': None
        }
        
        if not content or len(content) == 0:
            return result
            
        try:
            if YARA_AVAILABLE and self.compiled_rules:
                # Use YARA scanning
                yara_matches = self.compiled_rules.match(data=content)
                
                for match in yara_matches:
                    rule_meta = match.meta
                    
                    match_info = {
                        'rule': match.rule,
                        'category': rule_meta.get('category', 'unknown'),
                        'severity': rule_meta.get('severity', 'medium'),
                        'description': rule_meta.get('description', ''),
                        'matched_strings': []
                    }
                    
                    # Extract matched strings (limited to prevent huge outputs)
                    for string_match in match.strings[:5]:
                        match_info['matched_strings'].append({
                            'offset': string_match[0] if isinstance(string_match, tuple) else string_match.instances[0].offset if hasattr(string_match, 'instances') else 0,
                            'identifier': string_match[1] if isinstance(string_match, tuple) else string_match.identifier if hasattr(string_match, 'identifier') else str(string_match),
                            'data': (string_match[2][:100] if isinstance(string_match, tuple) else 
                                    str(string_match.instances[0].matched_data)[:100] if hasattr(string_match, 'instances') else 
                                    str(string_match)[:100])
                        })
                    
                    result['matches'].append(match_info)
                    result['triggered_rules'].append(match.rule)
                    result['categories'].add(rule_meta.get('category', 'unknown'))
                    
                    # Track highest severity
                    severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}
                    current = severity_order.get(result['highest_severity'], 0)
                    new = severity_order.get(rule_meta.get('severity', 'medium'), 2)
                    if new > current:
                        result['highest_severity'] = rule_meta.get('severity', 'medium')
            else:
                # Fallback to regex scanning
                fallback_matches = self._fallback_scan(content)
                result['matches'] = fallback_matches
                result['triggered_rules'] = [m['rule'] for m in fallback_matches]
                result['categories'] = set(m['category'] for m in fallback_matches)
                
                if fallback_matches:
                    result['highest_severity'] = max(
                        fallback_matches, 
                        key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x['severity'], 0)
                    )['severity']
            
            result['total_matches'] = len(result['matches'])
            result['categories'] = list(result['categories'])
            
            if result['total_matches'] > 0:
                logger.warning(f"[YaraScanner] Found {result['total_matches']} matches: {result['triggered_rules']}")
            else:
                logger.info("[YaraScanner] No malicious patterns detected")
                
        except Exception as e:
            logger.error(f"[YaraScanner] Scan error: {e}")
            result['error'] = str(e)
        
        return result
    
    def scan_url_content(self, url: str, timeout: int = 10) -> Dict[str, Any]:
        """
        Fetch URL content and scan it with YARA rules.
        
        Args:
            url: URL to fetch and scan
            timeout: Request timeout in seconds
            
        Returns:
            Scan results
        """
        try:
            import requests
            
            response = requests.get(
                url, 
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 PhishingDetector/1.0'}
            )
            response.raise_for_status()
            
            return self.scan_content(response.text)
            
        except Exception as e:
            logger.error(f"[YaraScanner] Failed to fetch URL content: {e}")
            return {
                'matches': [],
                'triggered_rules': [],
                'categories': [],
                'highest_severity': 'none',
                'total_matches': 0,
                'error': f"Failed to fetch content: {e}"
            }


# Singleton instance
yara_scanner = YaraScanner()


def scan_content_with_yara(content: str) -> Dict[str, Any]:
    """
    Convenience function to scan content with YARA rules.
    
    Args:
        content: HTML/text content to scan
        
    Returns:
        Scan results with matches and severity
    """
    return yara_scanner.scan_content(content)


def is_yara_available() -> bool:
    """Check if YARA is available"""
    return YARA_AVAILABLE
