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
Automated Takedown Report Generator
Generates formal abuse reports for registrars and hosting providers
"""

import logging
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

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
        """Generate threat summary from scan results"""
        summaries = []
        
        verdict = scan_result.get('verdict', {})
        if isinstance(verdict, dict):
            if verdict.get('is_phishing'):
                summaries.append(f"Phishing detected with {verdict.get('confidence_score', 0):.1f}% confidence")
            threat_type = verdict.get('threat_type')
            if threat_type:
                summaries.append(f"Threat type: {threat_type}")
        
        # God Mode analysis
        god_mode = scan_result.get('god_mode_analysis', {})
        if god_mode and isinstance(god_mode, dict):
            if god_mode.get('verdict') == 'PHISHING':
                summaries.append(f"AI Analysis: {god_mode.get('summary', 'Phishing confirmed')}")
            if god_mode.get('impersonation_target'):
                summaries.append(f"Impersonating: {god_mode.get('impersonation_target')}")
        
        # YARA matches
        yara_result = scan_result.get('yara_analysis', {})
        if yara_result and yara_result.get('triggered_rules'):
            rules = yara_result.get('triggered_rules', [])
            summaries.append(f"Malicious patterns detected: {', '.join(rules[:3])}")
        
        return '; '.join(summaries) if summaries else "Phishing indicators detected"
    
    def _get_evidence_list(self, scan_result: Dict[str, Any]) -> List[str]:
        """Extract evidence points from scan results"""
        evidence = []
        
        # Technical details
        tech_details = scan_result.get('technical_details', {})
        if tech_details:
            if tech_details.get('ssl_age_hours') and tech_details['ssl_age_hours'] < 48:
                evidence.append(f"SSL certificate is only {tech_details['ssl_age_hours']} hours old")
            if tech_details.get('entropy_score') and tech_details['entropy_score'] > 4.5:
                evidence.append("High entropy JavaScript detected (likely obfuscated)")
        
        # Redirect chain
        forensics = scan_result.get('forensics', {})
        if forensics and forensics.get('redirect_chain'):
            chain = forensics.get('redirect_chain', [])
            if len(chain) > 2:
                evidence.append(f"Multiple redirect hops detected ({len(chain)} URLs)")
        
        # Vision analysis
        vision = scan_result.get('vision_analysis', {})
        if vision:
            evasion = vision.get('evasion', {})
            if evasion and evasion.get('evasion_detected'):
                evidence.append("Evasion techniques detected (hidden content)")
            connections = vision.get('connections', {})
            if connections and connections.get('suspicious_ips'):
                evidence.append(f"Suspicious IP connections: {', '.join(connections['suspicious_ips'][:3])}")
        
        # RAG matches
        rag_matches = scan_result.get('rag_matches', [])
        if rag_matches:
            evidence.append("URL matches known phishing threat patterns in our database")
        
        return evidence
    
    def generate_abuse_report(
        self,
        url: str,
        scan_result: Dict[str, Any],
        osint_data: Optional[Dict[str, Any]] = None,
        reporter_name: str = "Phishing Detection System",
        reporter_org: str = "Automated Security Scanner"
    ) -> Dict[str, Any]:
        """
        Generate a formal abuse/takedown report.
        
        Args:
            url: The phishing URL
            scan_result: Full scan result dictionary
            osint_data: OSINT/WHOIS data for the domain
            reporter_name: Name of the reporter
            reporter_org: Organization name
            
        Returns:
            Dict with recipient, subject, body, and metadata
        """
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
