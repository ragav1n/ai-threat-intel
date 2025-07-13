import time
from pathlib import Path
from threat_summarizer import summarize_threat
from threat_summarizer.validator import validate_severity
from threat_summarizer.logger import log_summary
from threat_summarizer.emailer import send_batch_email, should_send_by_timer


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

def summarize_pending_iocs():
    seen = load_seen()
    summaries = []

    if INPUT_FILE.exists():
        lines = INPUT_FILE.read_text().splitlines()
        for line in lines:
            ioc = line.strip()
            if ioc and ioc not in seen:
                print(f"📥 New IOC: {ioc}")
                result = summarize_threat(ioc, model="llama2")
                validation = validate_severity(result["input"], result["severity"])
                result["corrected"] = False  # default

                if validation.startswith("INVALID"):
                    corrected = validation.split(":")[-1].strip()
                    print(f"[❗ SEVERITY MISMATCH] Auto-correcting → {corrected}")
                    result["original_severity"] = result["severity"]
                    result["severity"] = corrected
                    result["corrected"] = True
                else:
                    print("[✅ Severity Confirmed]")

                append_output(result, validation)

                log_summary(
                    result["input"],
                    result["summary"],
                    result["severity"],
                    corrected=result.get("corrected", False),
                    original_severity=result.get("original_severity", None)
                )

                save_seen(ioc)
                seen.add(ioc)
                summaries.append(result)

    return summaries


def append_output(result, validation_status):
    with open(OUTPUT_FILE, "a") as f:
        f.write("\n--- THREAT SUMMARY ---\n")
        f.write(f"Time: {result['timestamp']}\n")
        f.write(f"Severity: {result['severity']} ({validation_status})\n")
        f.write(f"Input: {result['input']}\n\n")
        f.write(result['summary'])
        f.write("\n")

def run_loop(poll_interval=5):
    seen = load_seen()
    high_threat_batch = []
    print("🟢 Monitoring input.txt for new IOCs...\n")

    while True:
        if INPUT_FILE.exists():
            lines = INPUT_FILE.read_text().splitlines()
            for line in lines:
                ioc = line.strip()
                if ioc and ioc not in seen:
                    print(f"📥 New IOC: {ioc}")

                    result = summarize_threat(ioc, model="llama2")
                    validation = validate_severity(result["input"], result["severity"])
                    result["corrected"] = False  # default

                    if validation.startswith("INVALID"):
                        corrected = validation.split(":")[-1].strip()
                        print(f"[❗ SEVERITY MISMATCH] Auto-correcting → {corrected}")
                        result["original_severity"] = result["severity"]
                        result["severity"] = corrected
                        result["corrected"] = True
                    else:
                        print("[✅ Severity Confirmed]")

                    append_output(result, validation)

                    log_summary(
                        result["input"],
                        result["summary"],
                        result["severity"],
                        corrected=result.get("corrected", False),
                        original_severity=result.get("original_severity", None)
                    )

                    # ✅ Batch and send logic INSIDE this block
                    # Collect high severity IOCs
                    if result["severity"] == "High" or (
                        result.get("corrected") and result["severity"] == "High"
                    ):
                        high_threat_batch.append(result)

                    # Trigger email by count OR timer
                    if len(high_threat_batch) >= 10 or should_send_by_timer(10):  # every 10 minutes
                        send_batch_email(high_threat_batch)
                        high_threat_batch.clear()


                    save_seen(ioc)
                    seen.add(ioc)


        time.sleep(poll_interval)

if __name__ == "__main__":
    run_loop()
