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
Phishing Kit Fingerprinting Service
Analyzes HTML source and URL path for signatures of known phishing kits.
"""

import re
import logging
from typing import Dict, Any, Optional, List

from app.core.kit_signatures import KIT_SIGNATURES

logger = logging.getLogger(__name__)


class KitDetector:
    """
    Detects known phishing kits by matching keywords and regex
    against HTML content and URL path (signatures left by kit developers).
    """

    @staticmethod
    def detect(
        html_content: Optional[str] = None,
        url_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Run phishing kit fingerprinting on HTML and URL path.

        Args:
            html_content: Raw HTML source of the page (or None).
            url_path: URL path + query (e.g. /login/verify.php?x=1) or full URL (or None).

        Returns:
            If any kit matches:
            {
                "detected": True,
                "kit_name": "Z118 (General/Vietnam)",
                "confidence": "High" | "Low",
                "matched_signatures": ["z118_login", "z118_admin"]
            }
            If nothing matches: None (or empty structure per spec).
        """
        if not html_content and not url_path:
            return None

        html_lower = (html_content or "").lower()
        path_lower = (url_path or "").lower()
        combined = f"{html_lower}\n{path_lower}"

        for kit_name, sig in KIT_SIGNATURES.items():
            keywords: List[str] = sig.get("keywords") or []
            regex_list: List[str] = sig.get("regex") or []
            matched: List[str] = []

            for kw in keywords:
                if kw.lower() in html_lower or kw.lower() in path_lower:
                    matched.append(kw)

            for pattern in regex_list:
                try:
                    if re.search(pattern, combined, re.IGNORECASE):
                        matched.append(f"regex:{pattern}")
                except re.error:
                    continue

            if not matched:
                continue

            confidence = "High" if len(matched) >= 2 else "Low"
            logger.info(f"[KitDetector] Match: {kit_name} (confidence={confidence}, matches={len(matched)})")
            return {
                "detected": True,
                "kit_name": kit_name,
                "confidence": confidence,
                "matched_signatures": matched,
            }

        return None
