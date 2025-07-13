import json
from datetime import datetime
from pathlib import Path

LOG_FILE = Path(__file__).parent.parent / "logs" / "summaries.jsonl"
LOG_FILE.parent.mkdir(exist_ok=True)

def log_summary(threat_input, summary, severity):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "input": threat_input,
        "summary": summary,
        "severity": severity
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
