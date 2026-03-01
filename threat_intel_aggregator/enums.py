"""
Enums for IOC types and severity levels used throughout the application.
"""
from enum import Enum
from typing import Dict


class IOCType(str, Enum):
    """Indicator of Compromise types."""
    IP = "ip"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    MAC_ADDRESS = "mac_address"
    ASN = "asn"
    CIDR = "cidr"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    CRYPTO_BTC = "crypto_btc"
    CRYPTO_ETH = "crypto_eth"
    CRYPTO_XMR = "crypto_xmr"
    TOR_V3 = "tor_v3"
    JA3 = "ja3"
    JA3S = "ja3s"
    JARM = "jarm"
    IMPHASH = "imphash"
    RICH_HEADER = "rich_header"
    CERT_SHA1 = "cert_sha1"
    AWS_IAM = "aws_iam"
    YARA_RULE = "yara_rule"
    PHONE_NUMBER = "phone_number"
    EMAIL_HEADER = "email_header"
    BEHAVIOR = "behavior"
    
    def __str__(self) -> str:
        return self.value
    
    @classmethod
    def from_string(cls, value: str) -> "IOCType":
        """Parse IOC type from string."""
        value_lower = value.lower()
        for ioc_type in cls:
            if ioc_type.value == value_lower:
                return ioc_type
        raise ValueError(f"Unknown IOC type: {value}")


class Severity(str, Enum):
    """Threat severity levels."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    UNKNOWN = "Unknown"
    
    def __str__(self) -> str:
        return self.value
    
    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse severity from string, case-insensitive."""
        value_lower = value.lower()
        for level in cls:
            if level.value.lower() in value_lower:
                return level
        return cls.UNKNOWN
    
    @property
    def priority(self) -> int:
        """Get numeric priority for sorting (higher = more severe)."""
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
            Severity.UNKNOWN: 0,
        }.get(self, 0)


class FeedPriority(str, Enum):
    """Feed source priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def __str__(self) -> str:
        return self.value


class FeedSourceType(str, Enum):
    """Types of feed sources."""
    BLOG = "blog"
    GOVERNMENT = "government"
    GITHUB = "github"
    THREAT_FEED = "threat_feed"
    API = "api"
    RSS = "rss"
    
    def __str__(self) -> str:
        return self.value


# Mapping from IOC type to default severity
IOC_DEFAULT_SEVERITY: Dict[IOCType, Severity] = {
    IOCType.IP: Severity.MEDIUM,
    IOCType.IPV6: Severity.MEDIUM,
    IOCType.DOMAIN: Severity.MEDIUM,
    IOCType.URL: Severity.HIGH,
    IOCType.MD5: Severity.HIGH,
    IOCType.SHA1: Severity.HIGH,
    IOCType.SHA256: Severity.HIGH,
    IOCType.EMAIL: Severity.LOW,
    IOCType.CVE: Severity.CRITICAL,
    IOCType.MAC_ADDRESS: Severity.MEDIUM,
    IOCType.ASN: Severity.MEDIUM,
    IOCType.CIDR: Severity.HIGH,
    IOCType.REGISTRY_KEY: Severity.HIGH,
    IOCType.MUTEX: Severity.HIGH,
    IOCType.CRYPTO_BTC: Severity.HIGH,
    IOCType.CRYPTO_ETH: Severity.HIGH,
    IOCType.CRYPTO_XMR: Severity.HIGH,
    IOCType.TOR_V3: Severity.HIGH,
    IOCType.JA3: Severity.HIGH,
    IOCType.JA3S: Severity.HIGH,
    IOCType.JARM: Severity.HIGH,
    IOCType.IMPHASH: Severity.HIGH,
    IOCType.RICH_HEADER: Severity.HIGH,
    IOCType.CERT_SHA1: Severity.HIGH,
    IOCType.AWS_IAM: Severity.CRITICAL,
    IOCType.YARA_RULE: Severity.MEDIUM,
    IOCType.PHONE_NUMBER: Severity.MEDIUM,
    IOCType.EMAIL_HEADER: Severity.LOW,
    IOCType.BEHAVIOR: Severity.MEDIUM,
}


def get_severity_for_ioc_type(ioc_type: IOCType) -> Severity:
    """Get the default severity for an IOC type."""
    return IOC_DEFAULT_SEVERITY.get(ioc_type, Severity.UNKNOWN)
