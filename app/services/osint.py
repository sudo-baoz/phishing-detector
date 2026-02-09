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
OSINT Service - Open Source Intelligence Data Collection
Enriches scan results with WHOIS, DNS, and Geolocation data
"""

import logging
import socket
from typing import Optional, Dict, Any
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Try to import OSINT libraries
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed. Install with: pip install python-whois")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed. Install with: pip install dnspython")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests not installed. Install with: pip install requests")


def extract_domain(url: str) -> Optional[str]:
    """
    Extract domain from URL
    
    Args:
        url: Full URL string
        
    Returns:
        Domain name or None if parsing fails
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain if domain else None
        
    except Exception as e:
        logger.error(f"Error extracting domain from {url}: {e}")
        return None


def get_whois_info(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Get WHOIS information for a domain
    
    Args:
        domain: Domain name to lookup
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary with WHOIS data:
        {
            'available': bool,
            'creation_date': str,
            'expiration_date': str,
            'registrar': str,
            'domain_age_days': int,
            'status': list
        }
    """
    result = {
        'available': False,
        'creation_date': None,
        'expiration_date': None,
        'registrar': None,
        'domain_age_days': None,
        'status': None,
        'error': None
    }
    
    if not WHOIS_AVAILABLE:
        result['error'] = "WHOIS library not available"
        return result
    
    try:
        logger.info(f"Fetching WHOIS data for: {domain}")
        
        # Perform WHOIS lookup with timeout
        w = whois.whois(domain)
        
        result['available'] = True
        
        # Extract creation date
        if w.creation_date:
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                result['creation_date'] = creation.strftime('%Y-%m-%d') if isinstance(creation, datetime) else str(creation)
                
                # Calculate domain age (handle timezone-aware datetime)
                if isinstance(creation, datetime):
                    try:
                        # Remove timezone info for comparison
                        if creation.tzinfo is not None:
                            creation = creation.replace(tzinfo=None)
                        age = datetime.now() - creation
                        result['domain_age_days'] = age.days
                    except Exception as e:
                        logger.debug(f"Could not calculate domain age: {e}")
        
        # Extract expiration date
        if w.expiration_date:
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            if expiration:
                result['expiration_date'] = expiration.strftime('%Y-%m-%d') if isinstance(expiration, datetime) else str(expiration)
        
        # Extract registrar
        if w.registrar:
            result['registrar'] = w.registrar if isinstance(w.registrar, str) else w.registrar[0] if isinstance(w.registrar, list) else str(w.registrar)
        
        # Extract status
        if w.status:
            result['status'] = w.status if isinstance(w.status, list) else [w.status]
        
        logger.info(f"[OK] WHOIS data retrieved for {domain}")
        
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        result['error'] = str(e)
    
    return result


def get_dns_info(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Get DNS information for a domain
    
    Args:
        domain: Domain name to lookup
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary with DNS data:
        {
            'available': bool,
            'a_records': list[str],  # IP addresses
            'mx_records': list[str],  # Mail servers
            'ns_records': list[str],  # Name servers
            'txt_records': list[str]  # TXT records
        }
    """
    result = {
        'available': False,
        'a_records': [],
        'mx_records': [],
        'ns_records': [],
        'txt_records': [],
        'error': None
    }
    
    if not DNS_AVAILABLE:
        result['error'] = "DNS library not available"
        return result
    
    try:
        logger.info(f"Fetching DNS data for: {domain}")
        
        # Configure DNS resolver with timeout
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        result['available'] = True
        
        # Get A records (IPv4 addresses)
        try:
            a_records = resolver.resolve(domain, 'A')
            result['a_records'] = [str(rdata) for rdata in a_records]
        except Exception as e:
            logger.debug(f"No A records for {domain}: {e}")
        
        # Get MX records (Mail servers)
        try:
            mx_records = resolver.resolve(domain, 'MX')
            result['mx_records'] = [str(rdata.exchange).rstrip('.') for rdata in mx_records]
        except Exception as e:
            logger.debug(f"No MX records for {domain}: {e}")
        
        # Get NS records (Name servers)
        try:
            ns_records = resolver.resolve(domain, 'NS')
            result['ns_records'] = [str(rdata).rstrip('.') for rdata in ns_records]
        except Exception as e:
            logger.debug(f"No NS records for {domain}: {e}")
        
        # Get TXT records
        try:
            txt_records = resolver.resolve(domain, 'TXT')
            result['txt_records'] = [str(rdata).strip('"') for rdata in txt_records]
        except Exception as e:
            logger.debug(f"No TXT records for {domain}: {e}")
        
        logger.info(f"[OK] DNS data retrieved for {domain}: {len(result['a_records'])} A records, {len(result['mx_records'])} MX records")
        
    except Exception as e:
        logger.warning(f"DNS lookup failed for {domain}: {e}")
        result['error'] = str(e)
    
    return result


def get_geolocation(ip: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Get geolocation information for an IP address using ip-api.com
    
    Args:
        ip: IP address to lookup
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary with geolocation data:
        {
            'available': bool,
            'country': str,
            'country_code': str,
            'region': str,
            'city': str,
            'isp': str,
            'org': str,
            'as': str,
            'latitude': float,
            'longitude': float
        }
    """
    result = {
        'available': False,
        'country': None,
        'country_code': None,
        'region': None,
        'city': None,
        'isp': None,
        'org': None,
        'as': None,
        'latitude': None,
        'longitude': None,
        'error': None
    }
    
    if not REQUESTS_AVAILABLE:
        result['error'] = "Requests library not available"
        return result
    
    try:
        logger.info(f"Fetching geolocation for IP: {ip}")
        
        # Use ip-api.com free API (no key required)
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,isp,org,as,lat,lon"
        
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get('status') == 'success':
            result['available'] = True
            result['country'] = data.get('country')
            result['country_code'] = data.get('countryCode')
            result['region'] = data.get('region')
            result['city'] = data.get('city')
            result['isp'] = data.get('isp')
            result['org'] = data.get('org')
            result['as'] = data.get('as')
            result['latitude'] = data.get('lat')
            result['longitude'] = data.get('lon')
            
            logger.info(f"[OK] Geolocation retrieved: {result['country']} ({result['isp']})")
        else:
            result['error'] = data.get('message', 'Unknown error')
            logger.warning(f"Geolocation failed for {ip}: {result['error']}")
        
    except Exception as e:
        logger.warning(f"Geolocation lookup failed for {ip}: {e}")
        result['error'] = str(e)
    
    return result


def collect_osint_data(url: str) -> Dict[str, Any]:
    """
    Collect all OSINT data for a URL (WHOIS + DNS + Geolocation)
    
    Args:
        url: Full URL to investigate
        
    Returns:
        Dictionary with all OSINT data:
        {
            'domain': str,
            'whois': {...},
            'dns': {...},
            'geolocation': {...},
            'primary_ip': str,
            'server_location': str
        }
    """
    osint_result = {
        'domain': None,
        'whois': None,
        'dns': None,
        'geolocation': None,
        'primary_ip': None,
        'server_location': None
    }
    
    try:
        # Extract domain from URL
        domain = extract_domain(url)
        if not domain:
            logger.warning(f"Could not extract domain from URL: {url}")
            return osint_result
        
        osint_result['domain'] = domain
        
        # Get WHOIS info
        osint_result['whois'] = get_whois_info(domain)
        
        # Get DNS info
        osint_result['dns'] = get_dns_info(domain)
        
        # Get geolocation for primary IP
        if osint_result['dns']['a_records']:
            primary_ip = osint_result['dns']['a_records'][0]
            osint_result['primary_ip'] = primary_ip
            
            osint_result['geolocation'] = get_geolocation(primary_ip)
            
            # Set server location
            if osint_result['geolocation']['available']:
                osint_result['server_location'] = osint_result['geolocation']['country']
        
        logger.info(f"[OK] OSINT data collection completed for {domain}")
        
    except Exception as e:
        logger.error(f"Error collecting OSINT data for {url}: {e}")
    
    return osint_result


def get_osint_summary(osint_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a summary of OSINT data for API response
    
    Args:
        osint_data: Full OSINT data from collect_osint_data()
        
    Returns:
        Simplified summary for API response
    """
    summary = {
        'domain': osint_data.get('domain'),
        'ip': osint_data.get('primary_ip'),
        'server_location': osint_data.get('server_location'),
        'lat': None,
        'lon': None,
        'isp': None,
        'registrar': None,
        'domain_age_days': None,
        'has_mail_server': False
    }
    # Geo for attack heatmap
    if osint_data.get('geolocation') and osint_data['geolocation'].get('available'):
        g = osint_data['geolocation']
        summary['lat'] = g.get('latitude')
        summary['lon'] = g.get('longitude')
    # Extract ISP
    if osint_data.get('geolocation') and osint_data['geolocation'].get('isp'):
        summary['isp'] = osint_data['geolocation']['isp']
    
    # Extract registrar and domain age
    if osint_data.get('whois'):
        summary['registrar'] = osint_data['whois'].get('registrar')
        summary['domain_age_days'] = osint_data['whois'].get('domain_age_days')
    
    # Check if has mail server
    if osint_data.get('dns') and osint_data['dns'].get('mx_records'):
        summary['has_mail_server'] = len(osint_data['dns']['mx_records']) > 0
    
    return summary
