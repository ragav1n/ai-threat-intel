"""
IOC (Indicator of Compromise) extraction from text using regex patterns.
"""
import re
import ipaddress
from typing import List, Tuple

from threat_intel_aggregator.enums import IOCType


# Regex patterns for each IOC type
IOC_PATTERNS: dict[IOCType, str] = {
    IOCType.IP: r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    IOCType.IPV6: r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b",
    IOCType.DOMAIN: r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    IOCType.URL: r"https?://[^\s\"'<>]+",
    IOCType.MD5: r"\b[a-fA-F\d]{32}\b",
    IOCType.SHA1: r"\b[a-fA-F\d]{40}\b",
    IOCType.SHA256: r"\b[a-fA-F\d]{64}\b",
    IOCType.EMAIL: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    IOCType.CVE: r"\bCVE-\d{4}-\d{4,}\b",
}

# Common false positives to filter out
DOMAIN_BLACKLIST = {
    "example.com", "localhost.localdomain", "test.com",
    "gmail.com", "yahoo.com", "hotmail.com",  # Email providers aren't IOCs
}


def is_valid_ip(ip_str: str) -> bool:
    """
    Validate IP address using the ipaddress module.
    The regex can match invalid IPs like 999.999.999.999.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_ipv6(ip_str: str) -> bool:
    """Validate IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 6
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private/reserved (not a threat indicator)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        return False


def extract_iocs(text: str, include_private_ips: bool = False) -> List[Tuple[str, IOCType]]:
    """
    Extract all IOCs from the given text.
    
    Args:
        text: The text to extract IOCs from.
        include_private_ips: Whether to include private/reserved IPs.
    
    Returns:
        List of tuples (ioc_value, ioc_type).
    """
    matches: List[Tuple[str, IOCType]] = []
    seen: set[str] = set()  # Deduplicate within same extraction
    
    for ioc_type, pattern in IOC_PATTERNS.items():
        found = re.findall(pattern, text)
        
        for item in found:
            # Skip duplicates
            if item in seen:
                continue
            
            # Validate and filter based on type
            if ioc_type == IOCType.IP:
                if not is_valid_ip(item):
                    continue
                if not include_private_ips and is_private_ip(item):
                    continue
                    
            elif ioc_type == IOCType.IPV6:
                if not is_valid_ipv6(item):
                    continue
                    
            elif ioc_type == IOCType.DOMAIN:
                if item.lower() in DOMAIN_BLACKLIST:
                    continue
            
            seen.add(item)
            matches.append((item, ioc_type))
    
    return matches


def extract_iocs_by_type(text: str, ioc_type: IOCType) -> List[str]:
    """Extract IOCs of a specific type only."""
    pattern = IOC_PATTERNS.get(ioc_type)
    if not pattern:
        return []
    
    found = re.findall(pattern, text)
    
    # Apply validation for IPs
    if ioc_type == IOCType.IP:
        found = [ip for ip in found if is_valid_ip(ip) and not is_private_ip(ip)]
    elif ioc_type == IOCType.IPV6:
        found = [ip for ip in found if is_valid_ipv6(ip)]
    
    return list(set(found))  # Deduplicate
