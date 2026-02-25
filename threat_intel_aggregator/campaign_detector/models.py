"""
Data models for detected threat campaigns.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from datetime import datetime
import hashlib
import json


@dataclass
class Campaign:
    """A detected cluster of related IOCs forming a coordinated campaign."""

    campaign_id: str
    label: str
    ioc_members: List[str]
    ioc_count: int
    first_seen: str  # ISO 8601
    last_seen: str   # ISO 8601
    duration_hours: float
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    type_distribution: Dict[str, int] = field(default_factory=dict)
    feed_sources: List[str] = field(default_factory=list)
    avg_confidence: float = 0.0
    max_confidence: float = 0.0
    detected_at: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        d = asdict(self)
        d["_id"] = self.campaign_id
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Campaign":
        """Reconstruct from a MongoDB document."""
        data.pop("_id", None)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class CampaignSummary:
    """Lightweight campaign model for list views."""

    campaign_id: str
    label: str
    ioc_count: int
    first_seen: str
    last_seen: str
    duration_hours: float
    avg_confidence: float
    top_severity: str = "Unknown"

    @classmethod
    def from_campaign(cls, c: Campaign) -> "CampaignSummary":
        """Create a summary from a full Campaign object."""
        top_sev = "Unknown"
        if c.severity_distribution:
            # Priority order: Critical > High > Medium > Low
            for sev in ["Critical", "High", "Medium", "Low"]:
                if c.severity_distribution.get(sev, 0) > 0:
                    top_sev = sev
                    break
        return cls(
            campaign_id=c.campaign_id,
            label=c.label,
            ioc_count=c.ioc_count,
            first_seen=c.first_seen,
            last_seen=c.last_seen,
            duration_hours=c.duration_hours,
            avg_confidence=c.avg_confidence,
            top_severity=top_sev,
        )


def generate_campaign_id(ioc_members: List[str]) -> str:
    """Generate a deterministic campaign ID from sorted IOC member list."""
    key = "|".join(sorted(ioc_members))
    return f"campaign_{hashlib.sha256(key.encode()).hexdigest()[:16]}"
