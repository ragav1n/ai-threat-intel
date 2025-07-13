# feed_collection/status.py
from datetime import datetime
import os

def print_last_fetch_status():
    path = "data/last_fetched.txt"
    if not os.path.exists(path):
        print("ℹ️  No previous fetch recorded.")
        return

    with open(path, "r") as f:
        last_time = datetime.fromisoformat(f.read().strip())

    delta = datetime.now() - last_time
    minutes_ago = int(delta.total_seconds() / 60)
    print(f"🕒 Last feed fetch was {minutes_ago} minutes ago.")
