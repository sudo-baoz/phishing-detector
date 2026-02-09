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
Automated Takedown Report Generator + Forensic PDF Reports
Generates formal abuse reports and professional PDF forensic reports.
"""

import base64
import io
import logging
import re
import textwrap
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas as pdf_canvas
    from reportlab.lib.utils import ImageReader
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates automated abuse/takedown reports for phishing sites.
    Extracts registrar abuse contacts and formats professional reports.
    """
    
    # Common registrar abuse email patterns
    REGISTRAR_ABUSE_EMAILS = {
        'godaddy': 'abuse@godaddy.com',
        'namecheap': 'abuse@namecheap.com',
        'cloudflare': 'abuse@cloudflare.com',
        'google': 'registrar-abuse@google.com',
        'tucows': 'domainabuse@tucows.com',
        'enom': 'abuse@enom.com',
        'network solutions': 'abuse@networksolutions.com',
        'register.com': 'abuse@register.com',
        'name.com': 'abuse@name.com',
        'porkbun': 'abuse@porkbun.com',
        'dynadot': 'abuse@dynadot.com',
        'hover': 'abuse@hover.com',
        'gandi': 'abuse@gandi.net',
        'ovh': 'abuse@ovh.net',
        'hostinger': 'abuse@hostinger.com',
        'bluehost': 'abuse@bluehost.com',
        'hostgator': 'abuse@hostgator.com',
        'ionos': 'abuse@ionos.com',
        'strato': 'abuse@strato.de',
        'epik': 'abuse@epik.com'
    }
    
    # Hosting provider abuse emails
    HOSTING_ABUSE_EMAILS = {
        'amazon': 'abuse@amazonaws.com',
        'aws': 'abuse@amazonaws.com',
        'google cloud': 'abuse@google.com',
        'microsoft azure': 'abuse@microsoft.com',
        'digitalocean': 'abuse@digitalocean.com',
        'linode': 'abuse@linode.com',
        'vultr': 'abuse@vultr.com',
        'ovh': 'abuse@ovh.net',
        'hetzner': 'abuse@hetzner.com',
        'contabo': 'abuse@contabo.com',
        'hostinger': 'abuse@hostinger.com'
    }
    
    def __init__(self):
        self.report_counter = 0
        
    def _extract_abuse_email_from_whois(self, osint_data: Dict[str, Any]) -> Optional[str]:
        """
        Extract abuse email from WHOIS/OSINT data.
        """
        if not osint_data:
            return None
            
        # Try direct abuse email field
        abuse_email = osint_data.get('abuse_email') or osint_data.get('registrar_abuse_email')
        if abuse_email and self._is_valid_email(abuse_email):
            return abuse_email
        
        # Try to find in raw WHOIS data
        raw_whois = osint_data.get('raw_whois', '')
        if raw_whois:
            # Look for abuse email pattern
            abuse_patterns = [
                r'Abuse[- ]Contact[- ]Email:\s*([^\s]+@[^\s]+)',
                r'Registrar Abuse Contact Email:\s*([^\s]+@[^\s]+)',
                r'abuse[- ]?mailbox:\s*([^\s]+@[^\s]+)',
                r'abuse@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ]
            
            for pattern in abuse_patterns:
                match = re.search(pattern, raw_whois, re.IGNORECASE)
                if match:
                    email = match.group(1) if match.lastindex else match.group(0)
                    if self._is_valid_email(email):
                        return email
        
        # Try to match registrar name to known abuse email
        registrar = osint_data.get('registrar', '').lower()
        for key, email in self.REGISTRAR_ABUSE_EMAILS.items():
            if key in registrar:
                return email
        
        # Try hosting provider
        asn_desc = osint_data.get('asn_description', '').lower()
        for key, email in self.HOSTING_ABUSE_EMAILS.items():
            if key in asn_desc:
                return email
                
        return None
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email format"""
        if not email:
            return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email.strip()))
    
    def _get_threat_summary(self, scan_result: Dict[str, Any]) -> str:
        """Generate threat summary from scan results (null-safe)"""
        # Null safety: Return default if no data
        if not scan_result:
            return "Phishing indicators detected"
            
        summaries = []
        
        verdict = scan_result.get('verdict') or {}
        if isinstance(verdict, dict):
            if verdict.get('is_phishing'):
                confidence = verdict.get('confidence_score') or 0
                summaries.append(f"Phishing detected with {confidence:.1f}% confidence")
            threat_type = verdict.get('threat_type')
            if threat_type:
                summaries.append(f"Threat type: {threat_type}")
        
        # God Mode analysis (null-safe)
        god_mode = scan_result.get('god_mode_analysis') or {}
        if god_mode and isinstance(god_mode, dict):
            if god_mode.get('verdict') == 'PHISHING':
                summary_text = god_mode.get('summary') or 'Phishing confirmed'
                summaries.append(f"AI Analysis: {summary_text}")
            impersonation = god_mode.get('impersonation_target')
            if impersonation:
                summaries.append(f"Impersonating: {impersonation}")
        
        # YARA matches (null-safe)
        yara_result = scan_result.get('yara_analysis') or {}
        if yara_result and isinstance(yara_result, dict):
            triggered_rules = yara_result.get('triggered_rules') or []
            if triggered_rules:
                summaries.append(f"Malicious patterns detected: {', '.join(str(r) for r in triggered_rules[:3])}")
        
        return '; '.join(summaries) if summaries else "Phishing indicators detected"
    
    def _get_evidence_list(self, scan_result: Dict[str, Any]) -> List[str]:
        """Extract evidence points from scan results (null-safe)"""
        # Null safety: Return empty list if no data
        if not scan_result:
            return ["Phishing indicators detected"]
            
        evidence = []
        
        # Technical details (null-safe)
        tech_details = scan_result.get('technical_details') or {}
        if tech_details and isinstance(tech_details, dict):
            ssl_age = tech_details.get('ssl_age_hours')
            if ssl_age and ssl_age < 48:
                evidence.append(f"SSL certificate is only {ssl_age} hours old")
            entropy = tech_details.get('entropy_score')
            if entropy and entropy > 4.5:
                evidence.append("High entropy JavaScript detected (likely obfuscated)")
        
        # Redirect chain (null-safe)
        forensics = scan_result.get('forensics') or {}
        if forensics and isinstance(forensics, dict):
            chain = forensics.get('redirect_chain') or []
            if len(chain) > 2:
                evidence.append(f"Multiple redirect hops detected ({len(chain)} URLs)")
        
        # Vision analysis (null-safe - this was crashing!)
        vision = scan_result.get('vision_analysis') or {}
        if vision and isinstance(vision, dict):
            evasion = vision.get('evasion') or {}
            if isinstance(evasion, dict) and evasion.get('evasion_detected'):
                evidence.append("Evasion techniques detected (hidden content)")
            connections = vision.get('connections') or {}
            if isinstance(connections, dict):
                suspicious_ips = connections.get('suspicious_ips') or []
                if suspicious_ips:
                    evidence.append(f"Suspicious IP connections: {', '.join(str(ip) for ip in suspicious_ips[:3])}")
        
        # RAG matches (null-safe)
        rag_matches = scan_result.get('rag_matches') or []
        if rag_matches:
            evidence.append("URL matches known phishing threat patterns in our database")
        
        return evidence if evidence else ["Multiple phishing indicators detected"]
    
    def generate_abuse_report(
        self,
        url: str,
        scan_result: Dict[str, Any],
        osint_data: Optional[Dict[str, Any]] = None,
        reporter_name: str = "Phishing Detection System",
        reporter_org: str = "Automated Security Scanner"
    ) -> Dict[str, Any]:
        """
        Generate a formal abuse/takedown report (null-safe).
        
        Args:
            url: The phishing URL
            scan_result: Full scan result dictionary
            osint_data: OSINT/WHOIS data for the domain
            reporter_name: Name of the reporter
            reporter_org: Organization name
            
        Returns:
            Dict with recipient, subject, body, and metadata
            Returns error dict if inputs are invalid
        """
        # ================================================================
        # NULL SAFETY: Validate all inputs before processing
        # ================================================================
        if not url:
            logger.warning("[ReportGenerator] Cannot generate report: URL is empty")
            return {
                'error': 'missing_url',
                'report_id': None,
                'generated': False
            }
        
        # Ensure scan_result is a valid dict
        if not scan_result or not isinstance(scan_result, dict):
            logger.warning("[ReportGenerator] Cannot generate report: scan_result is None or invalid")
            scan_result = {}  # Use empty dict to prevent crashes
        
        # Ensure osint_data is a valid dict
        if osint_data is None or not isinstance(osint_data, dict):
            osint_data = {}
        
        self.report_counter += 1
        
        try:
            # Extract domain info
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Get abuse email
            abuse_email = self._extract_abuse_email_from_whois(osint_data)
            registrar = osint_data.get('registrar', 'Unknown Registrar') if osint_data else 'Unknown Registrar'
            
            # Get server info
            server_ip = osint_data.get('ip') or osint_data.get('server_ip', 'Unknown') if osint_data else 'Unknown'
            asn_info = osint_data.get('asn_description', 'Unknown ASN') if osint_data else 'Unknown ASN'
            
            # Generate evidence and summary
            threat_summary = self._get_threat_summary(scan_result)
            evidence_list = self._get_evidence_list(scan_result)
            
            # Get confidence score
            verdict = scan_result.get('verdict', {})
            confidence = verdict.get('confidence_score', 0) if isinstance(verdict, dict) else 0
            
            # Timestamp
            timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            report_id = f"RPT-{datetime.now().strftime('%Y%m%d')}-{self.report_counter:04d}"
            
            # Build email subject
            subject = f"[URGENT] Phishing Site Report - {domain} - {report_id}"
            
            # Build email body
            body = f"""
================================================================================
                    AUTOMATED PHISHING ABUSE REPORT
================================================================================
Report ID: {report_id}
Generated: {timestamp}
Reporter: {reporter_name} ({reporter_org})

--------------------------------------------------------------------------------
                           INCIDENT DETAILS
--------------------------------------------------------------------------------

MALICIOUS URL: {url}
DOMAIN: {domain}
SERVER IP: {server_ip}
HOSTING/ASN: {asn_info}
REGISTRAR: {registrar}

--------------------------------------------------------------------------------
                           THREAT ANALYSIS
--------------------------------------------------------------------------------

VERDICT: PHISHING
CONFIDENCE: {confidence:.1f}%
SUMMARY: {threat_summary}

EVIDENCE:
{chr(10).join(f'  • {e}' for e in evidence_list) if evidence_list else '  • Multiple phishing indicators detected'}

--------------------------------------------------------------------------------
                           REQUESTED ACTION
--------------------------------------------------------------------------------

We respectfully request that you take immediate action to:

1. SUSPEND the domain "{domain}" to prevent further phishing attacks
2. PRESERVE all associated logs for potential law enforcement investigation
3. NOTIFY us of the action taken at your earliest convenience

This phishing site poses a direct threat to internet users by attempting to 
steal credentials and/or financial information through deceptive practices.

--------------------------------------------------------------------------------
                           DISCLAIMER
--------------------------------------------------------------------------------

This report was generated automatically by an AI-powered threat detection 
system. The evidence provided has been collected through non-intrusive 
scanning methods. All findings are based on heuristic analysis and pattern 
matching against known phishing indicators.

If you require additional evidence or have questions about this report,
please contact us through appropriate channels.

================================================================================
                     END OF AUTOMATED REPORT - {report_id}
================================================================================
"""
            
            # Generate result
            result = {
                'report_id': report_id,
                'generated_at': timestamp,
                'recipient': abuse_email,
                'recipient_found': abuse_email is not None,
                'registrar': registrar,
                'subject': subject,
                'body': body.strip(),
                'domain': domain,
                'url': url,
                'confidence_score': confidence,
                'evidence_count': len(evidence_list),
                'metadata': {
                    'server_ip': server_ip,
                    'asn': asn_info,
                    'threat_summary': threat_summary
                }
            }
            
            logger.info(f"[ReportGenerator] Generated abuse report {report_id} for {domain}")
            
            if not abuse_email:
                logger.warning(f"[ReportGenerator] No abuse email found for registrar: {registrar}")
                result['fallback_recipients'] = [
                    'abuse@' + domain.split('.')[-2] + '.' + domain.split('.')[-1] if '.' in domain else None,
                    'postmaster@' + domain if domain else None
                ]
            
            return result
            
        except Exception as e:
            logger.error(f"[ReportGenerator] Failed to generate report: {e}")
            return {
                'report_id': None,
                'error': str(e),
                'recipient': None,
                'subject': None,
                'body': None
            }
    
    def generate_hosting_report(
        self,
        url: str,
        scan_result: Dict[str, Any],
        osint_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate abuse report specifically for hosting providers.
        Similar to registrar report but targeted at hosting/ASN abuse contacts.
        """
        # Get hosting abuse email
        hosting_email = None
        if osint_data:
            asn_desc = osint_data.get('asn_description', '').lower()
            for key, email in self.HOSTING_ABUSE_EMAILS.items():
                if key in asn_desc:
                    hosting_email = email
                    break
        
        # Generate standard report and modify recipient
        report = self.generate_abuse_report(url, scan_result, osint_data)
        
        if hosting_email:
            report['hosting_recipient'] = hosting_email
            report['subject'] = report['subject'].replace('[URGENT]', '[URGENT - HOSTING]')
        
        return report


# Singleton instance
report_generator = ReportGenerator()


def generate_abuse_report(
    url: str,
    scan_result: Dict[str, Any],
    osint_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to generate abuse report.

    Args:
        url: Phishing URL
        scan_result: Full scan result
        osint_data: Optional OSINT/WHOIS data

    Returns:
        Abuse report dict with recipient, subject, body
    """
    return report_generator.generate_abuse_report(url, scan_result, osint_data)


# =============================================================================
# FORENSIC PDF REPORT (Canvas-based, rich content)
# =============================================================================

def _safe_str(v: Any, default: str = "N/A") -> str:
    if v is None:
        return default
    s = str(v).strip()
    return s if s else default


def generate_pdf(scan_data: Dict[str, Any]) -> io.BytesIO:
    """
    Generate a comprehensive Forensic Analysis Report PDF using reportlab Canvas.
    Sections: Header, Executive Summary, Technical Intelligence, AI Analysis, Visual Evidence.
    Footer strictly: "Generated automatically by CyberSentinel AI".
    """
    buf = io.BytesIO()
    if not REPORTLAB_AVAILABLE:
        logger.warning("reportlab not installed. Install with: pip install reportlab")
        return buf

    c = pdf_canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    margin = 50
    y = height - margin
    line_height = 14
    small_line = 11

    def _draw_heading(text: str, font_size: int = 14) -> None:
        nonlocal y
        c.setFont("Helvetica-Bold", font_size)
        c.drawString(margin, y, text)
        y -= line_height + 4

    def _draw_text(text: str, font_size: int = 10) -> None:
        nonlocal y
        c.setFont("Helvetica", font_size)
        c.drawString(margin, y, text[:120] if len(text) > 120 else text)
        y -= line_height

    def _wrap_draw(long_text: str, wrap_width: int = 85, font_size: int = 10) -> None:
        nonlocal y
        if not long_text or not isinstance(long_text, str):
            return
        c.setFont("Helvetica", font_size)
        for line in textwrap.wrap(long_text, width=wrap_width):
            if y < margin + 40:
                c.showPage()
                y = height - margin
            c.drawString(margin, y, line[:100])
            y -= line_height

    def _new_page_if_needed(need: int = 80) -> None:
        nonlocal y
        if y < margin + need:
            c.showPage()
            y = height - margin

    # ----- Header: Project Name, Date, Scan ID -----
    c.setFont("Helvetica-Bold", 18)
    c.drawString(margin, y, "CYBER SENTINEL - FORENSIC REPORT")
    y -= line_height + 4
    scan_id = scan_data.get("id") or scan_data.get("scan_id") or "N/A"
    scanned_at = scan_data.get("scanned_at")
    if hasattr(scanned_at, "strftime"):
        date_str = scanned_at.strftime("%Y-%m-%d %H:%M UTC")
    else:
        date_str = _safe_str(scanned_at) if scanned_at else "N/A"
    c.setFont("Helvetica", 10)
    c.drawString(margin, y, f"Date: {date_str}  |  Scan ID: {scan_id}")
    y -= line_height * 2

    # ----- Executive Summary -----
    _draw_heading("Executive Summary", 12)
    url = _safe_str(scan_data.get("url"))
    _draw_text(f"URL: {url}")
    verdict = scan_data.get("verdict") or {}
    if isinstance(verdict, dict):
        score = verdict.get("score")
        if score is None:
            score = scan_data.get("confidence_score", 0)
        level = (verdict.get("level") or "").upper()
        is_phishing = (
            scan_data.get("is_phishing")
            if "is_phishing" in scan_data
            else (level in ("CRITICAL", "HIGH") or (score or 0) >= 50)
        )
    else:
        score = scan_data.get("confidence_score", 0)
        is_phishing = scan_data.get("is_phishing", False)
    c.setFont("Helvetica-Bold", 11)
    if is_phishing:
        c.setFillColorRGB(0.9, 0.2, 0.2)
        c.drawString(margin, y, "Verdict: PHISHING")
        c.setFillColorRGB(0, 0, 0)
    else:
        c.setFillColorRGB(0.1, 0.7, 0.3)
        c.drawString(margin, y, "Verdict: SAFE")
        c.setFillColorRGB(0, 0, 0)
    y -= line_height
    c.setFont("Helvetica", 10)
    c.drawString(margin, y, f"Risk Score: {score}/100")
    y -= line_height * 2

    # ----- Technical Intelligence (table) -----
    _draw_heading("Technical Intelligence", 12)
    network = scan_data.get("network") or {}
    tech = scan_data.get("technical_details") or {}
    advanced = scan_data.get("advanced") or {}
    ssl_issuer = _safe_str(tech.get("ssl_issuer") or network.get("ssl_issuer"))
    ssl_validity = _safe_str(advanced.get("ssl_validity") or tech.get("ssl_validity"))
    server_headers = _safe_str(advanced.get("server") or tech.get("server_headers"))
    rows = [
        ("IP Address", _safe_str(network.get("ip"))),
        ("Country", _safe_str(network.get("country"))),
        ("Domain Age", _safe_str(network.get("domain_age"))),
        ("Registrar", _safe_str(network.get("registrar"))),
        ("SSL Issuer", ssl_issuer),
        ("SSL Validity", ssl_validity),
        ("Server Headers", server_headers),
    ]
    c.setFont("Helvetica-Bold", 9)
    c.drawString(margin, y, "Field")
    c.drawString(margin + 180, y, "Value")
    y -= line_height
    c.setFont("Helvetica", 9)
    for label, value in rows:
        if y < margin + 30:
            c.showPage()
            y = height - margin
        val_short = (value[:70] + "..") if len(value) > 70 else value
        c.drawString(margin, y, label)
        c.drawString(margin + 180, y, val_short)
        y -= small_line
    y -= line_height

    # ----- AI Analysis (full summary, wrapped) -----
    _new_page_if_needed(120)
    _draw_heading("AI Analysis", 12)
    ai_text = None
    god = scan_data.get("god_mode_analysis") or {}
    if isinstance(god, dict) and god.get("summary"):
        ai_text = god.get("summary")
    if not ai_text and isinstance(verdict, dict) and verdict.get("ai_conclusion"):
        ai_text = verdict.get("ai_conclusion")
    if ai_text:
        _wrap_draw(ai_text, wrap_width=85, font_size=10)
    else:
        _draw_text("No AI summary available for this scan.")
    y -= line_height

    # ----- Visual Evidence: Desktop (large) + Mobile (smaller) -----
    _new_page_if_needed(200)
    _draw_heading("Visual Evidence", 12)
    screenshot_b64 = scan_data.get("screenshot_base64")
    img_w_desktop = 5.2 * inch
    img_h_desktop = 3.2 * inch
    if screenshot_b64:
        try:
            im_bytes = base64.b64decode(screenshot_b64, validate=True)
            reader = ImageReader(io.BytesIO(im_bytes))
            c.drawImage(reader, margin, y - img_h_desktop, width=img_w_desktop, height=img_h_desktop)
            y -= img_h_desktop + line_height
            c.setFont("Helvetica", 9)
            c.drawString(margin, y, "Desktop Screenshot")
            y -= line_height * 2
        except Exception as e:
            logger.debug("Failed to embed desktop screenshot: %s", e)
            _draw_text("Desktop screenshot could not be embedded.")
    else:
        _draw_text("Desktop screenshot not available for this scan.")
    mobile_b64 = scan_data.get("mobile_screenshot_base64")
    if mobile_b64:
        try:
            im_bytes = base64.b64decode(mobile_b64, validate=True)
            reader = ImageReader(io.BytesIO(im_bytes))
            mw, mh = 2.4 * inch, 3.6 * inch
            if y - mh < margin + 60:
                c.showPage()
                y = height - margin
            c.drawImage(reader, margin, y - mh, width=mw, height=mh)
            y -= mh + small_line
            c.setFont("Helvetica", 9)
            c.drawString(margin, y, "Mobile Screenshot")
            y -= line_height
        except Exception:
            pass

    # ----- Footer on final page -----
    c.showPage()
    c.setFont("Helvetica", 9)
    footer_text = "Generated automatically by CyberSentinel AI"
    c.drawString(margin, 30, footer_text)

    c.save()
    buf.seek(0)
    return buf
