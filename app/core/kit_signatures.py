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
Phishing Kit Signatures Library
Forensic fingerprints of known phishing kits (file names, variables, comments, paths).
Used by KitDetector to identify attacker tooling from HTML and URL structure.
"""

from typing import Dict, List, Any

# Structure: kit_name -> { "keywords": [...], "regex": [r"...", ...] }
# Keywords are matched case-insensitively in HTML and URL path.
# Regex are applied to normalized (lowercase) content.
KIT_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "16Shop (Apple/Amazon)": {
        "keywords": [
            "16shop",
            "unusual_login.php",
            "admin/panel/",
            "assets/js/kit.js",
            "16_shop",
            "sixteenshop",
            "admin_panel",
        ],
        "regex": [
            r"16shop",
            r"16_shop",
            r"sixteen[\s_-]?shop",
        ],
    },
    "Z118 (General/Vietnam)": {
        "keywords": [
            "z118",
            "z118_login",
            "z118_admin",
            "z118_panel",
            "z118_config",
            "z118/assets",
        ],
        "regex": [
            r"z118_[a-z]+",
            r"z118[\s\-]?(login|admin|panel|config)",
        ],
    },
    "Kr3pto (Crypto Wallets)": {
        "keywords": [
            "kr3pto",
            "import_wallet",
            "seed_phrase",
            "recovery_phrase",
            "connect_wallet",
            "kr3pto_",
        ],
        "regex": [
            r"kr3pto",
            r"seed[\s_-]?phrase",
            r"import[\s_-]?wallet",
        ],
    },
    "NextGen Bank": {
        "keywords": [
            "nextgen",
            "verification/index.php",
            "scamalytics",
            "nextgen_bank",
            "ng_bank",
        ],
        "regex": [
            r"nextgen",
            r"scamalytics",
        ],
    },
    "HeartBleed Kit": {
        "keywords": [
            "hb_admin",
            "hb_config",
            "heartbleed",
            "hb_panel",
        ],
        "regex": [
            r"hb_[a-z]+",
            r"heart[\s_-]?bleed",
        ],
    },
    "Generic Anti-Bot": {
        "keywords": [
            "antibot",
            "botblocker",
            "is_bot.php",
            "check_bot",
            "anti_bot",
            "human_verify",
        ],
        "regex": [
            r"anti[\s_-]?bot",
            r"bot[\s_-]?blocker",
            r"is_bot\.php",
        ],
    },
    "Ex-Robots (Russian Phishing Kit)": {
        "keywords": [
            "ex-robots",
            "exrobots",
            "ex_robots",
            "robots.php",
        ],
        "regex": [
            r"ex[\s\-_]?robots",
        ],
    },
    "Manuscrape": {
        "keywords": [
            "manuscrape",
            "manuscrape_",
            "ms_config",
        ],
        "regex": [
            r"manuscrape",
        ],
    },
    "Dolphin (PhishLabs)": {
        "keywords": [
            "dolphin_phish",
            "dolphin/config",
            "phishlabs",
        ],
        "regex": [
            r"dolphin[\s_-]?(phish|config)",
        ],
    },
    "Ankos (Banking)": {
        "keywords": [
            "ankos",
            "ankos_panel",
            "ankos_admin",
        ],
        "regex": [
            r"ankos",
        ],
    },
    "Greatness (OAuth/2FA)": {
        "keywords": [
            "greatness",
            "greatness_panel",
            "oauth_callback",
            "two_factor_verify",
        ],
        "regex": [
            r"greatness",
        ],
    },
    "Yahoo Phishing Kit": {
        "keywords": [
            "yahoo_phish",
            "yahoo_login_kit",
            "yahoo_verify.php",
        ],
        "regex": [
            r"yahoo[\s_-]?(phish|verify|login[\s_-]?kit)",
        ],
    },
    "Phenix (French Banking)": {
        "keywords": [
            "phenix",
            "phenix_panel",
            "phenix_admin",
        ],
        "regex": [
            r"phenix",
        ],
    },
}
