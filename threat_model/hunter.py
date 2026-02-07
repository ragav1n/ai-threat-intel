"""
Hunter module - IOC enrichment with network intelligence.
Provides geolocation, WHOIS, and DNS resolution for IPs and domains.
"""
import re
import socket
from typing import Optional

import requests

# Optional whois - may not be installed
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


# IP regex pattern
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Request timeout
REQUEST_TIMEOUT = 5


def is_ip(text: str) -> bool:
    """Check if text is an IPv4 address."""
    return bool(IP_PATTERN.match(text))


def get_ip_info(ip: str) -> str:
    """
    Get geolocation and organization info for an IP address.
    Uses ipinfo.io API.
    """
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            city = data.get("city", "Unknown")
            region = data.get("region", "")
            country = data.get("country", "")
            org = data.get("org", "Unknown")
            location = ", ".join(filter(None, [city, region, country]))
            return f"Geolocation: {location}. Org: {org}."
    except requests.RequestException:
        pass
    return "Geolocation: Unknown."


def get_whois_info(domain: str) -> str:
    """
    Get WHOIS registration info for a domain.
    """
    if not WHOIS_AVAILABLE:
        return "Whois: Module not available."
    
    try:
        w = whois.whois(domain)
        registrar = w.registrar or "Unknown"
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return f"Registrar: {registrar}. Created: {creation_date}."
    except Exception:
        return "Whois: Lookup failed."


def resolve_domain(domain: str) -> Optional[str]:
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def enrich_ioc(ioc: str) -> str:
    """
    Analyze an IOC and return enrichment context.
    
    Args:
        ioc: The IOC to analyze (IP, domain, or URL).
        
    Returns:
        Enrichment string with network intelligence.
    """
    enrichment = []
    
    # Clean IOC - remove protocol and path
    clean_ioc = ioc.replace("http://", "").replace("https://", "").split("/")[0]

    if is_ip(clean_ioc):
        enrichment.append(f"[Hunter] IP detected: {clean_ioc}")
        enrichment.append(get_ip_info(clean_ioc))
        
    elif "." in clean_ioc and " " not in clean_ioc:
        enrichment.append(f"[Hunter] Domain/URL detected: {clean_ioc}")
        enrichment.append(get_whois_info(clean_ioc))
        
        # Resolve IP
        resolved_ip = resolve_domain(clean_ioc)
        if resolved_ip:
            enrichment.append(f"Resolved IP: {resolved_ip}")
            enrichment.append(get_ip_info(resolved_ip))
        else:
            enrichment.append("DNS Resolution: Failed")
    
    if not enrichment:
        return "No network enrichment available."
         
    return " ".join(enrichment)
