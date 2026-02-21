from pathlib import Path
from .github_discovery import discover_github_atom_feeds

# Try to import from centralized config
try:
    import sys
    import os
    # Add root to path if needed for config import
    root_path = Path(__file__).resolve().parent.parent.parent
    if str(root_path) not in sys.path:
        sys.path.append(str(root_path))
    from config import DATA_DIR, BASE_DIR as ROOT_BASE_DIR
except ImportError:
    ROOT_BASE_DIR = Path(__file__).resolve().parent.parent
    DATA_DIR = ROOT_BASE_DIR / "data"

# === Path Configuration ===
BASE_DIR = Path(__file__).resolve().parent.parent

# Feed Files
FEED_FILE = BASE_DIR / "feed_collection" / "feeds.yaml"

# All dynamic data files rewritten to centralized DATA_DIR
RAW_FEED_OUTPUT = DATA_DIR / "raw_feeds.json"
FEED_HEALTH_FILE = DATA_DIR / "feed_health.json"
FEED_HEALTH_CSV = DATA_DIR / "feed_health_history.csv"
FETCH_LOG_FILE = DATA_DIR / "feed_collector.log"
LAST_FETCHED_FILE = DATA_DIR / "last_fetched.txt"

# IOC Output Files
NORMALIZED_IOC_JSON = DATA_DIR / "normalized_iocs.json"
NORMALIZED_IOC_CSV = DATA_DIR / "normalized_iocs.csv"

# === Feed Loading Functions ===
import yaml

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
