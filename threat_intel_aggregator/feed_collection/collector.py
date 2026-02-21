"""
Feed collection with concurrent fetching and retry logic.
"""
import json
import logging
from typing import Dict, Any, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .config import RAW_FEED_OUTPUT, FETCH_LOG_FILE, load_feed_metadata
from .health import update_feed_health


# Configure rotating log handler
handler = RotatingFileHandler(FETCH_LOG_FILE, maxBytes=1_000_000, backupCount=3)
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# Default headers to avoid being blocked
DEFAULT_HEADERS = {
    "User-Agent": "AI-ThreatIntel-Aggregator/2.0 (+https://github.com/ragav1n/ai-threat-intel)",
    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
}


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((requests.RequestException, requests.Timeout)),
)
def fetch_with_retry(url: str, timeout: int = 15) -> requests.Response:
    """
    Fetch URL with retry logic using exponential backoff.
    
    Args:
        url: URL to fetch.
        timeout: Request timeout in seconds.
        
    Returns:
        Response object.
    """
    response = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout)
    response.raise_for_status()
    return response


def fetch_feed(feed_info: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Fetch a single feed and return the result.
    
    Args:
        feed_info: Feed configuration dictionary.
        
    Returns:
        Tuple of (feed_name, result_dict).
    """
    name = feed_info.get("name", "Unnamed Feed")
    url = feed_info["url"]
    source_type = feed_info.get("source_type", "rss")
    category = feed_info.get("category", "unknown")

    try:
        logging.info(f"🔄 Fetching: {name} ({url})")
        response = fetch_with_retry(url)
        
        content = response.text
        response_time = response.elapsed.total_seconds()
        
        logging.info(f"✅ Success: [{name}] ({len(content.splitlines())} lines, {response_time:.2f}s)")
        update_feed_health(feed_info, response_time, success=True)

        return name, {
            "status": "success",
            "url": url,
            "content": content,
            "category": category,
            "source_type": source_type,
            "reliability": feed_info.get("reliability", 0.5),
            "response_time": response_time,
        }

    except Exception as e:
        logging.error(f"❌ Failed after retries: [{name}] - {e}")
        update_feed_health(feed_info, 0, success=False)
        return name, {
            "status": "failed",
            "url": url,
            "error": str(e),
            "category": category,
            "source_type": source_type,
            "reliability": feed_info.get("reliability", 0.5),
        }


def collect_feeds_concurrently(max_workers: int = 10) -> Dict[str, Any]:
    """
    Collect all configured feeds concurrently.
    
    Args:
        max_workers: Maximum number of concurrent threads.
        
    Returns:
        Dictionary of feed results.
    """
    feeds = load_feed_metadata()
    results: Dict[str, Any] = {}
    
    success_count = 0
    failure_count = 0
    
    logging.info(f"🚀 Starting concurrent fetch of {len(feeds)} feeds...")
    print(f"\n🚀 Fetching {len(feeds)} feeds concurrently...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_feed = {executor.submit(fetch_feed, feed): feed for feed in feeds}
        
        for future in as_completed(future_to_feed):
            name, result = future.result()
            results[name] = result
            
            if result["status"] == "success":
                success_count += 1
                print(f"  ✅ {name}")
            else:
                failure_count += 1
                print(f"  ❌ {name}: {result.get('error', 'Unknown error')}")

    # Save results
    with open(RAW_FEED_OUTPUT, "w") as f:
        json.dump(results, f, indent=2)

    summary = f"📦 Completed: {success_count} success, {failure_count} failed"
    logging.info(summary)
    print(f"\n{summary}")
    
    return results


def get_feed_stats() -> Dict[str, Any]:
    """Get statistics about the last feed collection."""
    try:
        with open(RAW_FEED_OUTPUT, "r") as f:
            results = json.load(f)
        
        success = sum(1 for r in results.values() if r.get("status") == "success")
        failed = sum(1 for r in results.values() if r.get("status") == "failed")
        
        return {
            "total": len(results),
            "success": success,
            "failed": failed,
            "success_rate": f"{(success / len(results) * 100):.1f}%" if results else "0%",
        }
    except FileNotFoundError:
        return {"total": 0, "success": 0, "failed": 0, "success_rate": "0%"}