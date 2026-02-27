"""
IOC (Indicator of Compromise) extraction from text with confidence scoring.

Enhancements:
- Multi-factor confidence scoring based on pattern quality, context, and validation
- Improved false positive filtering
- Context-aware extraction
"""
import re
import ipaddress
import logging
from typing import List, Tuple, Dict, Any, Optional
from dataclasses import dataclass

from threat_intel_aggregator.enums import IOCType
from threat_intel_aggregator.feed_collection.ioc_deobfuscator import deobfuscate_text

logger = logging.getLogger(__name__)


# Regex patterns for each IOC type
IOC_PATTERNS: dict[IOCType, str] = {
    IOCType.IP: r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    IOCType.IPV6: r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b",
    IOCType.DOMAIN: r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    IOCType.URL: r"(?:https?|ftp)://[^\s\"'<>]+",
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
    "google.com", "microsoft.com", "github.com",  # Common legitimate domains
    "outlook.com", "live.com", "icloud.com", "protonmail.com",
    "linkedin.com", "twitter.com", "facebook.com", "apple.com",
    "amazon.com", "cloudflare.com", "mozilla.org",
}

# File extensions that look like domains but aren't IOCs
FILE_EXTENSION_BLACKLIST = {
    ".exe", ".dll", ".sys", ".bin", ".dat", ".tmp",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".js", ".php", ".html", ".htm", ".css", ".asp", ".aspx", ".jsp",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".py", ".rb", ".java", ".cpp", ".go", ".rs",
    ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg", ".log",
    ".iso", ".img", ".dmg", ".apk", ".msi",
}

# High-value TLDs that increase confidence
HIGH_RISK_TLDS = {".ru", ".cn", ".top", ".xyz", ".tk", ".pw", ".cc", ".ws"}

# Threat context keywords that increase confidence
THREAT_CONTEXT_KEYWORDS = {
    "malware", "malicious", "threat", "attack", "exploit", "vulnerability",
    "ransomware", "phishing", "trojan", "backdoor", "botnet", "c2", "c&c",
    "compromise", "infected", "suspicious", "ioc", "indicator", "apt",
    "campaign", "actor", "payload", "dropper", "loader", "rat",
}

# Base confidence scores by IOC type
IOC_TYPE_BASE_CONFIDENCE: Dict[IOCType, float] = {
    IOCType.SHA256: 0.85,   # Very specific, low false positive
    IOCType.SHA1: 0.80,     # Specific but less common now
    IOCType.MD5: 0.75,      # Less secure but still good indicator
    IOCType.URL: 0.70,      # Context-dependent
    IOCType.IP: 0.60,       # Could be legitimate
    IOCType.IPV6: 0.60,
    IOCType.DOMAIN: 0.55,   # High false positive potential
    IOCType.CVE: 0.90,      # Structured identifier
    IOCType.EMAIL: 0.50,    # Often benign
}


@dataclass
class IOCMatch:
    """Represents an extracted IOC with confidence score."""
    value: str
    ioc_type: IOCType
    confidence: float
    context_snippet: str = ""
    deobfuscated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "ioc": self.value,
            "type": str(self.ioc_type),
            "confidence": round(self.confidence, 2),
            "deobfuscated": self.deobfuscated,
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


# RFC 5737 documentation ranges — these are NOT private and should be extractable
_DOCUMENTATION_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
]


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private/reserved (not a threat indicator).
    
    Note: RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) are treated as public for IOC extraction purposes,
    since they are commonly used in threat reports as example IOCs.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        # Allow documentation ranges through (commonly used as example IOCs)
        for net in _DOCUMENTATION_RANGES:
            if addr in net:
                return False
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        return False


def get_context_window(text: str, match_start: int, match_end: int, window_size: int = 100) -> str:
    """Extract context around a match for confidence scoring."""
    start = max(0, match_start - window_size)
    end = min(len(text), match_end + window_size)
    return text[start:end].lower()


def calculate_context_boost(context: str) -> float:
    """
    Calculate confidence boost based on surrounding context.
    
    Returns a value between 0.0 and 0.2 based on threat-related keywords.
    """
    keyword_count = sum(1 for kw in THREAT_CONTEXT_KEYWORDS if kw in context)
    
    # More keywords = higher confidence, max boost of 0.2
    if keyword_count >= 3:
        return 0.20
    elif keyword_count >= 2:
        return 0.15
    elif keyword_count >= 1:
        return 0.10
    return 0.0


def calculate_ip_confidence(ip_str: str, context: str) -> float:
    """Calculate confidence score for IP addresses."""
    base = IOC_TYPE_BASE_CONFIDENCE[IOCType.IP]
    
    # Penalize common legitimate IPs
    if ip_str.startswith("8.8.") or ip_str.startswith("1.1.1."):  # Google/Cloudflare DNS
        base -= 0.30
    
    # Boost for private IPs mentioned in threat context (internal compromise)
    if is_private_ip(ip_str):
        if any(kw in context for kw in ["lateral", "internal", "pivot"]):
            base += 0.10
        else:
            base -= 0.20
    
    # Add context boost
    base += calculate_context_boost(context)
    
    return max(0.1, min(1.0, base))


def calculate_domain_confidence(domain: str, context: str) -> float:
    """Calculate confidence score for domains."""
    base = IOC_TYPE_BASE_CONFIDENCE[IOCType.DOMAIN]
    
    # Check TLD risk
    domain_lower = domain.lower()
    for tld in HIGH_RISK_TLDS:
        if domain_lower.endswith(tld):
            base += 0.15
            break
    
    # Long random-looking subdomains often malicious
    parts = domain.split('.')
    if len(parts) > 2:
        subdomain = parts[0]
        if len(subdomain) > 15:
            base += 0.10
        if any(c.isdigit() for c in subdomain) and any(c.isalpha() for c in subdomain):
            base += 0.05  # Mixed alphanumeric subdomains
    
    # Add context boost
    base += calculate_context_boost(context)
    
    return max(0.1, min(1.0, base))


def calculate_hash_confidence(hash_value: str, ioc_type: IOCType, context: str) -> float:
    """Calculate confidence score for hash values."""
    base = IOC_TYPE_BASE_CONFIDENCE.get(ioc_type, 0.7)
    
    # All-zero or repeating patterns are likely placeholders
    if len(set(hash_value.lower())) < 4:
        base -= 0.40
    
    # Add context boost
    base += calculate_context_boost(context)
    
    return max(0.1, min(1.0, base))


def calculate_url_confidence(url: str, context: str) -> float:
    """Calculate confidence score for URLs."""
    base = IOC_TYPE_BASE_CONFIDENCE[IOCType.URL]
    
    url_lower = url.lower()
    
    # Check for suspicious patterns
    if any(pattern in url_lower for pattern in ["/wp-admin", "/phishing", "/payload", ".exe", ".zip", ".rar"]):
        base += 0.15
    
    # High-risk TLDs in URL
    for tld in HIGH_RISK_TLDS:
        if tld in url_lower:
            base += 0.10
            break
    
    # Long URLs more suspicious
    if len(url) > 150:
        base += 0.05
    
    # Add context boost
    base += calculate_context_boost(context)
    
    return max(0.1, min(1.0, base))


def calculate_confidence(
    ioc_value: str, 
    ioc_type: IOCType, 
    context: str
) -> float:
    """
    Calculate confidence score for an IOC extraction.
    
    Args:
        ioc_value: The extracted IOC.
        ioc_type: Type of IOC.
        context: Surrounding text context.
        
    Returns:
        Confidence score between 0.0 and 1.0.
    """
    if ioc_type == IOCType.IP:
        return calculate_ip_confidence(ioc_value, context)
    elif ioc_type == IOCType.DOMAIN:
        return calculate_domain_confidence(ioc_value, context)
    elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        return calculate_hash_confidence(ioc_value, ioc_type, context)
    elif ioc_type == IOCType.URL:
        return calculate_url_confidence(ioc_value, context)
    elif ioc_type == IOCType.CVE:
        return min(1.0, IOC_TYPE_BASE_CONFIDENCE[IOCType.CVE] + calculate_context_boost(context))
    else:
        # Default for EMAIL and others
        return min(1.0, IOC_TYPE_BASE_CONFIDENCE.get(ioc_type, 0.5) + calculate_context_boost(context))


def extract_iocs(text: str, include_private_ips: bool = False) -> List[Tuple[str, IOCType]]:
    """
    Extract all IOCs from the given text (legacy interface).
    
    Args:
        text: The text to extract IOCs from.
        include_private_ips: Whether to include private/reserved IPs.
    
    Returns:
        List of tuples (ioc_value, ioc_type).
    """
    matches = extract_iocs_with_confidence(text, include_private_ips)
    return [(m.value, m.ioc_type) for m in matches]


def extract_iocs_with_confidence(
    text: str, 
    include_private_ips: bool = False,
    min_confidence: float = 0.0
) -> List[IOCMatch]:
    """
    Extract all IOCs from the given text with confidence scores.
    
    Args:
        text: The text to extract IOCs from.
        include_private_ips: Whether to include private/reserved IPs.
        min_confidence: Minimum confidence threshold (0.0-1.0).
    
    Returns:
        List of IOCMatch objects with confidence scores.
    """
    matches: List[IOCMatch] = []
    seen: set[str] = set()  # Deduplicate within same extraction
    
    # Phase 1: Deobfuscate text before regex matching
    text, was_deobfuscated = deobfuscate_text(text)
    if was_deobfuscated:
        logger.info("🔧 Text was deobfuscated before IOC extraction")
    
    # Phase 2: Extract URLs first so we can dedup domains later
    extracted_urls: set[str] = set()
    for match in re.finditer(IOC_PATTERNS[IOCType.URL], text):
        extracted_urls.add(match.group().lower())
    
    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in re.finditer(pattern, text):
            item = match.group()
            
            # Skip duplicates
            if item in seen:
                continue
            
            # Get context for confidence calculation
            context = get_context_window(text, match.start(), match.end())
            
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
                item_lower = item.lower()
                # Skip blacklisted domains
                if item_lower in DOMAIN_BLACKLIST:
                    continue
                # Skip file-extension-like matches (payload.exe, script.js, etc.)
                last_dot = item_lower.rfind('.')
                if last_dot >= 0:
                    extension = item_lower[last_dot:]
                    if extension in FILE_EXTENSION_BLACKLIST:
                        continue
                # Skip domains that are substrings of already-extracted URLs
                # (the URL itself is the more specific indicator)
                if any(item_lower in url for url in extracted_urls):
                    continue
            
            # Calculate confidence
            confidence = calculate_confidence(item, ioc_type, context)
            
            # Apply minimum threshold
            if confidence < min_confidence:
                continue
            
            seen.add(item)
            matches.append(IOCMatch(
                value=item,
                ioc_type=ioc_type,
                confidence=confidence,
                context_snippet=context[:50] if context else "",
                deobfuscated=was_deobfuscated,
            ))
    
    # Sort by confidence descending
    matches.sort(key=lambda m: m.confidence, reverse=True)
    
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
