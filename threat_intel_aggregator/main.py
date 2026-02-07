"""
Feed scheduler and main entry point for threat intelligence collection.
"""
import time
import logging
import traceback
from datetime import datetime
from typing import Optional, Dict, Any

import schedule

from threat_intel_aggregator.feed_collection.collector import collect_feeds_concurrently, get_feed_stats
from threat_intel_aggregator.feed_collection.parser import normalize_parsed_results
from threat_intel_aggregator.feed_collection.mongo_writer import (
    write_iocs_to_mongo, 
    export_iocs_to_summarizer_input,
    get_ioc_stats,
)

# Email imports
import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from tabulate import tabulate

# Try to use centralized config
try:
    from config import get_config
    config = get_config()
    SCHEDULER_INTERVAL = config.app.scheduler_interval_minutes
except ImportError:
    SCHEDULER_INTERVAL = 10


# Logging setup
logging.basicConfig(
    filename="data/feed_collector.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Global state
start_time = time.time()
failure_count = 0
MAX_FAILURES_BEFORE_ALERT = 3


def send_email_alert(
    subject: str, 
    body: str, 
    ioc_summary: Optional[Dict[str, Any]] = None, 
    attachment_path: Optional[str] = None, 
    uptime_minutes: Optional[float] = None
) -> bool:
    """
    Send email alert with optional IOC summary and attachment.
    
    Returns:
        True if email sent successfully, False otherwise.
    """
    # Email config (keeping as per user's request to not change credentials)
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    EMAIL_SENDER = "ragava22005@gmail.com"
    EMAIL_PASSWORD = "qkkk bmxq osso vkxe"
    EMAIL_RECIPIENT = "ragava2702@gmail.com"

    # Build email body
    full_body = body + "\n"

    if uptime_minutes is not None:
        full_body += f"\n🟢 Uptime: {uptime_minutes} minutes"

    if ioc_summary:
        full_body += "\n\n===== IOC SUMMARY =====\n"
        full_body += f"🕓 Timestamp: {ioc_summary.get('timestamp', 'N/A')}\n"
        full_body += f"🧮 Total IOCs: {ioc_summary.get('total', 0)}\n"
        full_body += f"🔍 Types: {', '.join(ioc_summary.get('types', []))}\n"

        samples = ioc_summary.get('samples', [])
        if samples:
            table_data = [[i + 1, ioc] for i, ioc in enumerate(samples)]
            full_body += "\n📋 Sample IOCs:\n"
            full_body += tabulate(table_data, headers=["#", "IOC"], tablefmt="grid")

    # Prepare message
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECIPIENT
    msg.attach(MIMEText(full_body))

    # Attach file if provided
    if attachment_path and os.path.exists(attachment_path):
        try:
            with open(attachment_path, "rb") as file:
                part = MIMEApplication(file.read(), Name=os.path.basename(attachment_path))
                part["Content-Disposition"] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                msg.attach(part)
        except Exception as e:
            print(f"⚠️ Could not attach file: {e}")

    # Send email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print("📧 Email alert sent!")
        return True
    except Exception as e:
        print(f"❌ Failed to send email alert: {e}")
        logging.error(f"❌ Email alert failed: {e}")
        return False


def load_ioc_summary() -> Optional[Dict[str, Any]]:
    """Load IOC summary from the normalized IOCs file."""
    try:
        with open("data/normalized_iocs.json", "r") as f:
            iocs = json.load(f)
            return {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total": len(iocs),
                "types": list({ioc.get("type", "unknown") for ioc in iocs}),
                "samples": [ioc.get("ioc", "N/A") for ioc in iocs[:5]],
            }
    except Exception as e:
        logging.warning(f"⚠️ Could not load IOC summary: {e}")
        return None


def send_alert(reason: str) -> None:
    """Send alert email with current IOC summary."""
    global start_time

    print(f"🚨 ALERT: {reason}")
    logging.error(f"🚨 ALERT: {reason}")

    ioc_summary = load_ioc_summary()
    uptime_minutes = round((time.time() - start_time) / 60, 2)
    
    subject = f"🚨 Feed Alert — {ioc_summary['total'] if ioc_summary else '?'} IOCs @ {datetime.now().strftime('%H:%M')}"

    send_email_alert(
        subject,
        body=reason,
        ioc_summary=ioc_summary,
        attachment_path="data/normalized_iocs.csv",
        uptime_minutes=uptime_minutes
    )


def scheduled_job() -> Dict[str, Any]:
    """
    Main scheduled job that collects feeds, extracts IOCs, and stores them.
    
    Returns:
        Dictionary with job statistics.
    """
    global failure_count
    
    stats = {"feeds": {}, "iocs": 0, "mongo": {}, "status": "success"}

    try:
        logging.info("📥 Feed Collection Started")
        print("\n" + "=" * 50)
        print("📥 Feed Collection Started")
        print("=" * 50)

        # Step 1: Collect feeds
        collect_feeds_concurrently()
        stats["feeds"] = get_feed_stats()

        # Step 2: Parse and normalize IOCs
        logging.info("🧪 Running IOC Parser")
        print("\n🧪 Parsing and normalizing IOCs...")
        normalized = normalize_parsed_results()
        stats["iocs"] = len(normalized)

        # Step 3: Write to MongoDB
        print("\n💾 Writing to MongoDB...")
        stats["mongo"] = write_iocs_to_mongo()

        # Step 4: Export to summarizer
        export_iocs_to_summarizer_input()

        logging.info("✅ Feed Collection Complete")
        print("\n" + "=" * 50)
        print("✅ Feed Collection Complete")
        print(f"   Feeds: {stats['feeds'].get('success', 0)}/{stats['feeds'].get('total', 0)}")
        print(f"   IOCs: {stats['iocs']} extracted, {stats['mongo'].get('inserted', 0)} new")
        print("=" * 50)
        
        failure_count = 0  # Reset on success

    except Exception as e:
        failure_count += 1
        stats["status"] = "failed"
        stats["error"] = str(e)
        
        logging.error("❌ Exception in scheduled job")
        logging.error(traceback.format_exc())
        print(f"❌ Exception in scheduled job: {e}")

        if failure_count >= MAX_FAILURES_BEFORE_ALERT:
            send_alert(f"Feed collector failed {failure_count} times in a row.")

    return stats


def start_scheduler() -> None:
    """Start the feed collection scheduler."""
    # Immediate first run
    scheduled_job()

    # Schedule recurring runs
    schedule.every(SCHEDULER_INTERVAL).minutes.do(scheduled_job)
    
    print(f"\n⏱️ Scheduler running every {SCHEDULER_INTERVAL} minutes...")
    next_run = schedule.next_run()
    print(f"🕒 Next scheduled feed collection at {next_run}")
    logging.info(f"🕒 Next scheduled feed collection at {next_run}")

    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except KeyboardInterrupt:
            print("\n👋 Scheduler stopped by user")
            break
        except Exception as e:
            logging.error("💥 Fatal error in scheduler loop")
            logging.error(traceback.format_exc())
            send_alert("Fatal error in scheduler loop. Restarting...")
            time.sleep(10)


if __name__ == "__main__":
    print("🚀 AI Threat Intel Aggregator")
    print("=" * 50)
    
    while True:
        try:
            start_scheduler()
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            logging.error("🔥 Unexpected crash in outer loop")
            logging.error(traceback.format_exc())
            send_alert("Restarting entire process after crash")
            time.sleep(30)