# feed_collection/config.py

import yaml
from pathlib import Path
from .github_discovery import discover_github_atom_feeds

# === Path Configuration ===
BASE_DIR = Path(__file__).resolve().parent.parent

# Feed + Health Files
FEED_FILE = BASE_DIR / "feed_collection" / "feeds.yaml"
RAW_FEED_OUTPUT = BASE_DIR / "data" / "raw_feeds.json"
FEED_HEALTH_FILE = BASE_DIR / "data" / "feed_health.json"
FEED_HEALTH_CSV = BASE_DIR / "data" / "feed_health_history.csv"
FETCH_LOG_FILE = BASE_DIR / "data" / "feed_collector.log"
LAST_FETCHED_FILE = BASE_DIR / "data" / "last_fetched.txt"

# IOC Output Files
NORMALIZED_IOC_JSON = BASE_DIR / "data" / "normalized_iocs.json"
NORMALIZED_IOC_CSV = BASE_DIR / "data" / "normalized_iocs.csv"

# === Feed Loading Functions ===

def load_static_feed_metadata(path=FEED_FILE):
    """
    Loads statically defined feeds from feeds.yaml.
    """
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return data["feeds"] if isinstance(data, dict) and "feeds" in data else data

def load_feed_metadata(path=FEED_FILE, include_github=True):
    """
    Loads both static and optionally auto-discovered GitHub feeds.
    """
    static_feeds = load_static_feed_metadata(path)
    if include_github:
        github_feeds = discover_github_atom_feeds()
        return static_feeds + github_feeds
    return static_feeds

def load_feed_urls(path=FEED_FILE):
    """
    Returns only the list of feed URLs (without metadata).
    """
    feeds = load_feed_metadata(path)
    return [feed["url"] for feed in feeds]
