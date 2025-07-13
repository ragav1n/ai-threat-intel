import json
import csv
from datetime import datetime
from pathlib import Path
from threat_summarizer.mongo_client import upload_summary

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

JSONL_FILE = LOG_DIR / "summaries.jsonl"
CSV_FILE = LOG_DIR / "summaries.csv"
JSON_FILE = LOG_DIR / "summaries.json"

def log_summary(threat_input, summary, severity, **kwargs):
    timestamp = datetime.utcnow().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "input": threat_input,
        "summary": summary,
        "severity": severity,
        "corrected": kwargs.get("corrected", False),
        "original_severity": kwargs.get("original_severity", None)
    }

    # 1. JSONL
    with open(JSONL_FILE, "a") as f_jsonl:
        f_jsonl.write(json.dumps(log_entry) + "\n")

    # 2. CSV
    is_new = not CSV_FILE.exists()
    with open(CSV_FILE, "a", newline='') as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=log_entry.keys())
        if is_new:
            writer.writeheader()
        writer.writerow(log_entry)

    # 3. Pretty JSON
    existing = []
    if JSON_FILE.exists():
        try:
            existing = json.loads(JSON_FILE.read_text())
        except json.JSONDecodeError:
            pass
    existing.append(log_entry)
    with open(JSON_FILE, "w") as f_json:
        json.dump(existing, f_json, indent=2)

    # 4. MongoDB Upload
    try:
        upload_summary(log_entry)
    except Exception as e:
        print(f"[⚠️ MongoDB Upload Failed] {e}")
