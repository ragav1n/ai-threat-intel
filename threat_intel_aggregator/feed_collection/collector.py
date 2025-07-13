# feed_collection/collector.py

import requests
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from .config import RAW_FEED_OUTPUT, FETCH_LOG_FILE
from .health import update_feed_health
from .config import load_feed_metadata

# Configure rotating log handler
handler = RotatingFileHandler(FETCH_LOG_FILE, maxBytes=1_000_000, backupCount=3)
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def fetch_feed(feed_info):
    name = feed_info.get("name", "Unnamed Feed")
    url = feed_info["url"]
    source_type = feed_info.get("source_type", "rss")
    category = feed_info.get("category", "unknown")

    try:
        logging.info(f"🔄 Trying to fetch: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        content = response.text
        logging.info(f"✅ Success: [{name}] ({len(content.splitlines())} lines)")

        update_feed_health(feed_info, response.elapsed.total_seconds(), success=True)

        return name, {
            "status": "success",
            "url": url,
            "content": content,
            "category": category,
            "source_type": source_type
        }

    except Exception as e:
        logging.error(f"❌ Retry failed: [{name}] - {e}")
        update_feed_health(feed_info, 0, success=False)
        return name, {
            "status": "failed",
            "url": url,
            "error": str(e)
        }

def collect_feeds_concurrently():
    feeds = load_feed_metadata()
    results = {}
    logging.info(f"🚀 Starting concurrent fetch of {len(feeds)} feeds...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_feed = {executor.submit(fetch_feed, feed): feed for feed in feeds}
        for future in as_completed(future_to_feed):
            name, result = future.result()
            results[name] = result

    with open(RAW_FEED_OUTPUT, "w") as f:
        json.dump(results, f, indent=2)

    logging.info(f"📦 Saved {len(results)} total entries to {RAW_FEED_OUTPUT}")

'''
Function-by-Function Explanation
1. is_duplicate(entry, existing_entries)
    Purpose:
    Checks if the same feed item (by title and link) already exists in the saved feed list.
    Why it matters:
    Avoids saving repeated items across fetch runs.

2. load_existing_entries(path)
Purpose:
Loads existing collected feed entries from a JSON file (raw_feeds.json).
Why it matters:
Keeps previous results intact and enables deduplication logic.

3. collect_feed_from_url(feed_info)
Purpose:

Downloads one feed (RSS or Atom) using parse_feed().

Logs success/failure.

Updates the feed’s health status (success_count, fail_count, etc.).

Why it matters:

Makes the system resilient via retry (tenacity handles retries).

Enables per-feed health scoring and error tracking.

4. collect_feeds_concurrently(save_to_file=True, out_path="data/raw_feeds.json")
Purpose:

Loads metadata for all feeds.

Concurrently fetches each feed using ThreadPoolExecutor.

Deduplicates new entries.

Saves the combined result into raw_feeds.json.

Updates last_fetched.txt with the latest fetch timestamp.

Why it matters:
This is your core orchestrator for feed ingestion and the foundation for your full pipeline.

Logging & Files Generated
File Path	Purpose
data/raw_feeds.json	Stores current list of collected entries
data/last_fetched.txt	Stores timestamp of last successful run
data/feed_collector.log	Logs all success/failure/info messages
data/feed_health.json	Tracks health of each feed (from health.py)



'''