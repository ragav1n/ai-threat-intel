import feedparser
from bs4 import BeautifulSoup
import re
from tenacity import retry, stop_after_attempt, wait_fixed
import json
import csv
import os
from datetime import datetime

from .ioc_extractor import extract_iocs
from .config import RAW_FEED_OUTPUT, NORMALIZED_IOC_JSON, NORMALIZED_IOC_CSV

IOC_SEVERITY = {
    "ip": "medium",
    "ipv6": "medium",
    "domain": "medium",
    "url": "high",
    "md5": "high",
    "sha1": "high",
    "sha256": "critical"
}

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def parse_feeds(url):
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

def normalize_and_store_iocs(feed_name, text, source_url, timestamp):
    iocs = extract_iocs(text)
    normalized_entries = []

    for ioc, ioc_type in iocs:
        entry = {
            "feed": feed_name,
            "ioc": ioc,
            "type": ioc_type,
            "severity": IOC_SEVERITY.get(ioc_type, "unknown"),
            "timestamp": timestamp,
            "source_url": source_url
        }
        normalized_entries.append(entry)

    return normalized_entries

def normalize_parsed_results():
    if not os.path.exists(RAW_FEED_OUTPUT):
        print("❌ No raw feed output to normalize.")
        return []

    with open(RAW_FEED_OUTPUT) as f:
        raw_data = json.load(f)

    normalized = []
    now = datetime.utcnow().isoformat() + "Z"

    for feed_name, data in raw_data.items():
        if data.get("status") != "success":
            continue

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
            for ioc in found_iocs:
                print(f"   • {ioc['type']} ({ioc['severity']}): {ioc['ioc']}")
            normalized.extend(found_iocs)
        else:
            print(f"⚠️  [{feed_name}] No IOCs found")

    try:
        with open(NORMALIZED_IOC_JSON, "w") as f:
            json.dump(normalized, f, indent=2)
    except Exception as e:
        print(f"❌ Failed to write normalized_iocs.json: {e}")

    try:
        with open(NORMALIZED_IOC_CSV, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["feed", "ioc", "type", "severity", "timestamp", "source_url"])
            writer.writeheader()
            for row in normalized:
                writer.writerow(row)
    except Exception as e:
        print(f"❌ Failed to write normalized_iocs.csv: {e}")

    print(f"\n📁 Saved {len(normalized)} normalized IOCs.")
    return normalized
