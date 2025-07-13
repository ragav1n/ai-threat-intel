import json
import csv
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent / "logs"
JSON_FILE = LOG_DIR / "summaries.json"
CSV_EXPORT = LOG_DIR / "export_filtered.csv"
JSON_EXPORT = LOG_DIR / "export_filtered.json"

def export_by_severity(severity: str = "High"):
    if not JSON_FILE.exists():
        print("[❌] No logs found.")
        return

    with open(JSON_FILE) as f:
        entries = json.load(f)

    filtered = [e for e in entries if e.get("severity") == severity]

    if not filtered:
        print(f"[⚠️] No entries found with severity '{severity}'")
        return

    # 🔁 Get union of all keys across entries
    all_keys = set()
    for entry in filtered:
        all_keys.update(entry.keys())
    fieldnames = list(all_keys)

    # Export JSON
    with open(JSON_EXPORT, "w") as jf:
        json.dump(filtered, jf, indent=2)

    # Export CSV
    with open(CSV_EXPORT, "w", newline='') as cf:
        writer = csv.DictWriter(cf, fieldnames=fieldnames)
        writer.writeheader()
        for entry in filtered:
            writer.writerow(entry)

    print(f"[✅] Exported {len(filtered)} '{severity}' entries to:")
    print(f" - {JSON_EXPORT}")
    print(f" - {CSV_EXPORT}")
