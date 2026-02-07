"""
Enums for IOC types and severity levels used throughout the application.
"""
from enum import Enum


class IOCType(str, Enum):
    """Indicator of Compromise types."""
    IP = "ip"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    
    def __str__(self) -> str:
        return self.value


class Severity(str, Enum):
    """Threat severity levels."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
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
