# feed_collection/health.py

import json
import os
import csv
from datetime import datetime
from .config import FEED_HEALTH_FILE

# New CSV history file to persist feed status logs
HEALTH_HISTORY_CSV = os.path.join(os.path.dirname(FEED_HEALTH_FILE), "feed_health_history.csv")

def load_health_data():
    if not os.path.exists(FEED_HEALTH_FILE):
        return {}

    with open(FEED_HEALTH_FILE, "r") as f:
        try:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
        except json.JSONDecodeError:
            print("⚠️ Warning: feed_health.json is empty or corrupted. Resetting health data.")
            return {}

def save_health_data(health):
    with open(FEED_HEALTH_FILE, "w") as f:
        json.dump(health, f, indent=2)

# 📈 Append row to CSV file every time a feed is checked
def log_health_to_csv(feed_name, success, response_time):
    timestamp = datetime.utcnow().isoformat()
    status = "success" if success else "failure"

    os.makedirs(os.path.dirname(HEALTH_HISTORY_CSV), exist_ok=True)
    file_exists = os.path.isfile(HEALTH_HISTORY_CSV)

    with open(HEALTH_HISTORY_CSV, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(["timestamp", "feed_name", "status", "response_time"])
        writer.writerow([timestamp, feed_name, status, response_time])

def update_feed_health(feed_info, response_time, success=True):
    name = feed_info.get("name", "Unnamed Feed")
    health = load_health_data()

    if name not in health:
        health[name] = {
            "success": 0,
            "failure": 0,
            "total": 0,
            "last_response_time": None
        }

    health[name]["total"] += 1
    if success:
        health[name]["success"] += 1
        health[name]["last_response_time"] = response_time
    else:
        health[name]["failure"] += 1

    save_health_data(health)
    log_health_to_csv(name, success, response_time)
