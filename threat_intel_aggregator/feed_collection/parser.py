"""
Feed content parsing and IOC normalization.
"""
import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any

import feedparser
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_fixed

from .ioc_extractor import extract_iocs
from .config import RAW_FEED_OUTPUT, NORMALIZED_IOC_JSON, NORMALIZED_IOC_CSV

# Import enums
try:
    from threat_intel_aggregator.enums import IOCType, Severity
except ImportError:
    from ..enums import IOCType, Severity


# Severity mapping based on IOC type
IOC_SEVERITY_MAP: Dict[IOCType, Severity] = {
    IOCType.IP: Severity.MEDIUM,
    IOCType.IPV6: Severity.MEDIUM,
    IOCType.DOMAIN: Severity.MEDIUM,
    IOCType.URL: Severity.HIGH,
    IOCType.MD5: Severity.HIGH,
    IOCType.SHA1: Severity.HIGH,
    IOCType.SHA256: Severity.HIGH,
}


def get_severity_for_ioc(ioc_type: IOCType) -> Severity:
    """Get the severity level for a given IOC type."""
    return IOC_SEVERITY_MAP.get(ioc_type, Severity.UNKNOWN)


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def parse_feeds(url: str) -> List[Dict[str, Any]]:
    """
    Parse RSS/Atom feed from URL with retry logic.
    
    Args:
        url: Feed URL to parse.
        
    Returns:
        List of parsed feed entries.
    """
    print(f"🔄 Trying to fetch: {url}")
    feed = feedparser.parse(url)

    if not feed.entries:
        raise ValueError(f"No entries found for {url}")

    entries = []
    for entry in feed.entries:
        entries.append({
            "source": feed.feed.get("title", "Unknown Source"),
            "title": entry.get("title", ""),
            "link": entry.get("link", ""),
            "summary": entry.get("summary", ""),
            "published": entry.get("published", ""),
            "feed_url": url
        })

    return entries


def normalize_and_store_iocs(
    feed_name: str, 
    text: str, 
    source_url: str, 
    timestamp: str
) -> List[Dict[str, Any]]:
    """
    Extract and normalize IOCs from text content.
    
    Args:
        feed_name: Name of the source feed.
        text: Text content to extract IOCs from.
        source_url: URL of the source.
        timestamp: ISO timestamp of extraction.
        
    Returns:
        List of normalized IOC entries.
    """
    iocs = extract_iocs(text)
    normalized_entries = []

    for ioc_value, ioc_type in iocs:
        severity = get_severity_for_ioc(ioc_type)
        entry = {
            "feed": feed_name,
            "ioc": ioc_value,
            "type": str(ioc_type),  # Convert enum to string for JSON
            "severity": str(severity),
            "timestamp": timestamp,
            "source_url": source_url
        }
        normalized_entries.append(entry)

    return normalized_entries


def normalize_parsed_results() -> List[Dict[str, Any]]:
    """
    Process raw feed data and extract normalized IOCs.
    
    Returns:
        List of all normalized IOC entries.
    """
    if not os.path.exists(RAW_FEED_OUTPUT):
        print("❌ No raw feed output to normalize.")
        return []

    with open(RAW_FEED_OUTPUT) as f:
        raw_data = json.load(f)

    normalized: List[Dict[str, Any]] = []
    now = datetime.utcnow().isoformat() + "Z"

    for feed_name, data in raw_data.items():
        if data.get("status") != "success":
            continue

        # Parse HTML content
        soup = BeautifulSoup(data.get("content", ""), "html.parser")
        clean_text = soup.get_text(separator=" ")

        found_iocs = normalize_and_store_iocs(
            feed_name=feed_name,
            text=clean_text,
            source_url=data.get("url"),
            timestamp=now
        )

        if found_iocs:
            print(f"✅ [{feed_name}] Found {len(found_iocs)} IOCs")
            for ioc in found_iocs[:5]:  # Only print first 5
                print(f"   • {ioc['type']} ({ioc['severity']}): {ioc['ioc']}")
            if len(found_iocs) > 5:
                print(f"   ... and {len(found_iocs) - 5} more")
            normalized.extend(found_iocs)
        else:
            print(f"⚠️  [{feed_name}] No IOCs found")

    # Save to JSON
    try:
        with open(NORMALIZED_IOC_JSON, "w") as f:
            json.dump(normalized, f, indent=2)
    except Exception as e:
        print(f"❌ Failed to write normalized_iocs.json: {e}")

    # Save to CSV
    try:
        with open(NORMALIZED_IOC_CSV, "w", newline="") as csvfile:
            fieldnames = ["feed", "ioc", "type", "severity", "timestamp", "source_url"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in normalized:
                writer.writerow(row)
    except Exception as e:
        print(f"❌ Failed to write normalized_iocs.csv: {e}")

    print(f"\n📁 Saved {len(normalized)} normalized IOCs.")
    return normalized
