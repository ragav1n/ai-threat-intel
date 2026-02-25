"""
Temporal analysis utilities for campaign detection.

Provides timeline generation and active campaign identification.
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

from .models import Campaign


def build_campaign_timeline(
    campaigns: List[Campaign],
    period_days: int = 30,
    bucket_size_days: int = 1,
) -> List[Dict[str, Any]]:
    """
    Generate time-series data showing campaign activity over time.

    Each data point contains a period label and the number of active
    campaigns during that time bucket.

    Args:
        campaigns: List of detected campaigns.
        period_days: How far back to look.
        bucket_size_days: Size of each time bucket in days.

    Returns:
        List of dicts: [{"period": "Feb 20", "active": 3, "new": 1}, ...]
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=period_days)
    step = timedelta(days=bucket_size_days)

    # Pre-parse campaign time ranges
    parsed_campaigns = []
    for c in campaigns:
        try:
            fs = datetime.fromisoformat(c.first_seen.replace("Z", "+00:00"))
            ls = datetime.fromisoformat(c.last_seen.replace("Z", "+00:00"))
            detected = datetime.fromisoformat(c.detected_at.replace("Z", "+00:00")) if c.detected_at else ls
            parsed_campaigns.append((fs, ls, detected))
        except (ValueError, TypeError):
            continue

    timeline = []
    current = start

    while current <= now:
        bucket_end = current + step
        label = current.strftime("%b %d")

        active = 0
        new = 0
        for fs, ls, detected in parsed_campaigns:
            # A campaign is "active" if its [first_seen, last_seen] overlaps the bucket
            if fs <= bucket_end and ls >= current:
                active += 1
            # A campaign is "new" if it was first detected in this bucket
            if current <= detected < bucket_end:
                new += 1

        timeline.append({
            "period": label,
            "active_campaigns": active,
            "new_campaigns": new,
        })
        current = bucket_end

    return timeline


def detect_active_campaigns(
    campaigns: List[Campaign],
    window_hours: float = 48,
) -> List[Campaign]:
    """
    Filter campaigns that have recent IOC activity.

    Args:
        campaigns: List of detected campaigns.
        window_hours: A campaign is "active" if its last_seen is within
                      this many hours from now.

    Returns:
        List of campaigns with recent activity.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=window_hours)
    active = []

    for c in campaigns:
        try:
            ls = datetime.fromisoformat(c.last_seen.replace("Z", "+00:00"))
            if ls >= cutoff:
                active.append(c)
        except (ValueError, TypeError):
            continue

    return active


def get_campaign_severity_summary(campaigns: List[Campaign]) -> Dict[str, int]:
    """
    Aggregate severity distribution across all campaigns.

    Returns:
        Dict like {"Critical": 5, "High": 12, ...}
    """
    totals: Dict[str, int] = defaultdict(int)
    for c in campaigns:
        for sev, count in c.severity_distribution.items():
            totals[sev] += count
    return dict(totals)
