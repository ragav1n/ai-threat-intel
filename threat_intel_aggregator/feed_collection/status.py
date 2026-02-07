"""
Feed status utilities - displays information about last fetch.
"""
from datetime import datetime
import os

from .config import LAST_FETCHED_FILE


def print_last_fetch_status() -> None:
    """Print information about the last feed fetch."""
    if not os.path.exists(LAST_FETCHED_FILE):
        print("ℹ️  No previous fetch recorded.")
        return

    try:
        with open(LAST_FETCHED_FILE, "r") as f:
            last_time = datetime.fromisoformat(f.read().strip())

        delta = datetime.now() - last_time
        minutes_ago = int(delta.total_seconds() / 60)
        
        if minutes_ago < 1:
            print("🕒 Last feed fetch was just now.")
        elif minutes_ago == 1:
            print("🕒 Last feed fetch was 1 minute ago.")
        else:
            print(f"🕒 Last feed fetch was {minutes_ago} minutes ago.")
            
    except (ValueError, OSError) as e:
        print(f"⚠️ Could not read last fetch time: {e}")


def get_last_fetch_time() -> datetime | None:
    """Get the timestamp of the last fetch, or None if not available."""
    if not os.path.exists(LAST_FETCHED_FILE):
        return None
    
    try:
        with open(LAST_FETCHED_FILE, "r") as f:
            return datetime.fromisoformat(f.read().strip())
    except (ValueError, OSError):
        return None
