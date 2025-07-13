import time
import logging
import schedule
import traceback
from feed_collection.collector import collect_feeds_concurrently
from feed_collection.parser import normalize_parsed_results
import smtplib
from email.mime.text import MIMEText
import json
from datetime import datetime
from tabulate import tabulate
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import os
from pymongo import MongoClient
from feed_collection.mongo_writer import write_iocs_to_mongo, export_iocs_to_summarizer_input

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel_db"]  # database
ioc_collection = db["iocs"]     # collection for IOCs
feed_health_collection = db["feed_health"]  # feed health status


start_time = time.time()

# Logging
logging.basicConfig(
    filename="data/feed_collector.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

failure_count = 0
MAX_FAILURES_BEFORE_ALERT = 3

def send_email_alert(subject, body, ioc_summary=None, attachment_path=None, uptime_minutes=None):
    from datetime import datetime

    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    EMAIL_SENDER = "ragava22005@gmail.com"
    EMAIL_PASSWORD = "qkkk bmxq osso vkxe"
    EMAIL_RECIPIENT = "ragava2702@gmail.com"

    # Construct full body
    full_body = body + "\n"

    if uptime_minutes is not None:
        full_body += f"\n🟢 Uptime: {uptime_minutes} minutes"

    if ioc_summary:
        full_body += "\n\n===== IOC SUMMARY =====\n"
        full_body += f"🕓 Timestamp: {ioc_summary['timestamp']}\n"
        full_body += f"🧮 Total IOCs: {ioc_summary['total']}\n"
        full_body += f"🔍 Types: {', '.join(ioc_summary['types'])}\n"

        table_data = [[i + 1, ioc] for i, ioc in enumerate(ioc_summary['samples'])]
        full_body += "\n📋 Sample IOCs:\n"
        full_body += tabulate(table_data, headers=["#", "IOC"], tablefmt="grid")

    # Prepare message with optional attachment
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECIPIENT
    msg.attach(MIMEText(full_body))

    # Attach file if provided
    if attachment_path:
        try:
            with open(attachment_path, "rb") as file:
                part = MIMEApplication(file.read(), Name=os.path.basename(attachment_path))
                part["Content-Disposition"] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                msg.attach(part)
        except Exception as e:
            print("⚠️ Could not attach file:", e)

    # Send email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print("📧 Email alert sent!")
    except Exception as e:
        print("❌ Failed to send email alert:", e)
        logging.error(f"❌ Email alert failed: {e}")




def send_alert(reason: str):
    global start_time

    print(f"🚨 ALERT: {reason}")
    logging.error(f"🚨 ALERT: {reason}")

    # Load IOC summary
    ioc_summary = None
    try:
        with open("data/normalized_iocs.json", "r") as f:
            iocs = json.load(f)
            ioc_summary = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total": len(iocs),
                "types": list({ioc.get("type", "unknown") for ioc in iocs}),
                "samples": [ioc.get("value", "N/A") for ioc in iocs[:5]],
            }
    except Exception as e:
        logging.warning(f"⚠️ Could not load IOC summary: {e}")

    # Calculate uptime
    uptime_minutes = round((time.time() - start_time) / 60, 2)

    # Compose subject
    subject = f"🚨 Feed Alert — {ioc_summary['total'] if ioc_summary else '?'} IOCs @ {datetime.now().strftime('%H:%M')}"

    send_email_alert(
        subject,
        body=reason,
        ioc_summary=ioc_summary,
        attachment_path="data/normalized_iocs.csv",
        uptime_minutes=uptime_minutes
    )


def scheduled_job():
    global failure_count
    

    try:
        logging.info("📥 Feed Collection Started")
        print("\n📥 Feed Collection Started")

        collect_feeds_concurrently()

        logging.info("🧪 Running IOC Parser")
        print("🧪 Running IOC Parser")
        normalize_parsed_results()

        logging.info("✅ Feed Collection Complete")
        print("✅ Feed Collection Complete")
        failure_count = 0  # Reset on success

    except Exception as e:
        failure_count += 1
        logging.error("❌ Exception in scheduled job")
        logging.error(traceback.format_exc())
        print("❌ Exception in scheduled job:", e)

        if failure_count >= MAX_FAILURES_BEFORE_ALERT:
            send_alert(f"Feed collector failed {failure_count} times in a row.")

    normalize_parsed_results()
    write_iocs_to_mongo()
    export_iocs_to_summarizer_input(output_txt_path="../threat_model/input.txt") # <- this line pushes IOCs to input.txt

def start_scheduler():
    # 🔁 Immediate first run
    scheduled_job()

    # 🕒 Schedule every 10 minutes
    schedule.every(10).minutes.do(scheduled_job)
    print("\n⏱️ Scheduler running every 10 minutes...\n")
    next_run = schedule.next_run()
    print(f"🕒 Next scheduled feed collection at {next_run}")
    logging.info(f"🕒 Next scheduled feed collection at {next_run}")

    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except Exception as e:
            logging.error("💥 Fatal error in scheduler loop")
            logging.error(traceback.format_exc())
            send_alert("Fatal error in scheduler loop. Restarting...")
            time.sleep(10)


if __name__ == "__main__":
    while True:
        try:
            start_scheduler()
        except Exception as e:
            logging.error("🔥 Unexpected crash in outer loop")
            logging.error(traceback.format_exc())
            send_alert("Restarting entire process after crash")
            time.sleep(30)  # Wait before restarting outer loop























'''
from apscheduler.schedulers.blocking import BlockingScheduler
from feed_collection.collector import collect_feeds_concurrently
from feed_collection.status import print_last_fetch_status
from feed_collection.parser import parse_feeds, normalize_parsed_results
from feed_collection.config import load_feed_metadata
import datetime
import json
import os
import pandas as pd

# Load and print feed metadata
feeds = load_feed_metadata()
for f in feeds:
    print(f"{f['name']} - {f['url']}")

def scheduled_job():
    print(f"\n🕒 Feed Collection Started at {datetime.datetime.now()}")

    # Step 1: Collect feeds
    collect_feeds_concurrently()
    print("📥 Feed Collection Complete.")

    # Step 2: Parse IOCs
    parsed = parse_feeds()

    # Step 3: Normalize IOCs
    normalized_iocs = normalize_parsed_results(parsed)

    # Output paths
    output_json_path = "data/normalized_iocs.json"
    output_csv_path = "data/normalized_iocs.csv"

    # Step 4: Save as JSON
    os.makedirs(os.path.dirname(output_json_path), exist_ok=True)
    with open(output_json_path, "w") as f:
        json.dump(normalized_iocs, f, indent=2)
    print(f"✅ Normalized IOCs saved to {output_json_path}")

    # Step 5: Save as CSV
    df = pd.DataFrame(normalized_iocs)
    df.to_csv(output_csv_path, index=False)
    print(f"📄 CSV export saved to {output_csv_path}")

if __name__ == "__main__":
    print_last_fetch_status()

    scheduler = BlockingScheduler()
    # scheduler.add_job(scheduled_job, 'interval', minutes=15)  # Production
    scheduler.add_job(scheduled_job, 'interval', seconds=20)    # Quick testing
    print("🚀 Scheduler running... Press Ctrl+C to exit.")
    scheduler.start()
'''