import time
from summarizer import summarize_threat
from pathlib import Path
from datetime import datetime

INPUT_FILE = Path("input.txt")
PROCESSED_FILE = Path("processed_inputs.txt")
OUTPUT_FILE = Path("output.txt")

def load_seen():
    if not PROCESSED_FILE.exists():
        return set()
    return set(PROCESSED_FILE.read_text().splitlines())

def save_seen(ioc):
    with open(PROCESSED_FILE, "a") as f:
        f.write(ioc.strip() + "\n")

def append_output(result):
    with open(OUTPUT_FILE, "a") as f:
        f.write("\n--- THREAT SUMMARY ---\n")
        f.write(f"Time: {result['timestamp']}\n")
        f.write(f"Severity: {result['severity']}\n")
        f.write(f"Input: {result['input']}\n\n")
        f.write(result['summary'])
        f.write("\n")

def run_loop(poll_interval=5):
    seen = load_seen()
    print("🟢 Monitoring input.txt for new IOCs...\n")

    while True:
        if INPUT_FILE.exists():
            lines = INPUT_FILE.read_text().splitlines()
            for line in lines:
                ioc = line.strip()
                if ioc and ioc not in seen:
                    print(f"📥 New IOC: {ioc}")
                    result = summarize_threat(ioc, model="llama2")
                    append_output(result)
                    save_seen(ioc)
                    seen.add(ioc)
                    print(f"✅ Summary for '{ioc}' saved (Severity: {result['severity']})\n")
        time.sleep(poll_interval)

if __name__ == "__main__":
    run_loop()
