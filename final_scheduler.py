import sys
import os
sys.path.append(os.path.abspath("."))
sys.path.append(os.path.abspath("./threat_model"))
sys.path.append(os.path.abspath("./threat_intel_aggregator"))

from apscheduler.schedulers.background import BackgroundScheduler
import time
import logging
from datetime import datetime
from threat_intel_aggregator.main import scheduled_job as collect_feeds
from threat_summarizer.watch_and_run import summarize_pending_iocs
from threat_summarizer.exporter import export_by_severity
from threat_summarizer.emailer import send_batch_email, should_send_by_timer
from pathlib import Path
import json
from threat_intel_aggregator.feed_collection.collector import collect_feeds_concurrently
from threat_intel_aggregator.feed_collection.parser import normalize_parsed_results
from threat_intel_aggregator.feed_collection.mongo_writer import write_iocs_to_mongo, export_iocs_to_summarizer_input

# Setup logging
logging.basicConfig(
    filename='logs/scheduler.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)

# Metrics
metrics = {
    "ioc_processed": 0,
    "emails_sent": 0,
    "errors_logged": 0
}

# Hold batched high severity threats
high_threat_batch = []

def safe_run(func, name):
    print(f"🟡 Running: {name}")
    try:
        logging.info(f"🔁 Starting job: {name}")
        result = func()
        print(f"✅ Finished: {name}")
        return result
    except Exception as e:
        metrics["errors_logged"] += 1
        logging.error(f"❌ Error in job '{name}': {type(e).__name__} - {e}")
        print(f"❌ Error in job '{name}': {e}")

def job_collect_feeds():
    result = safe_run(collect_feeds, "Collect Feeds")
    if result:
        logging.info(f"✅ Feeds collected: {result}")

def job_summarize():
    global high_threat_batch
    results = safe_run(summarize_pending_iocs, "Summarize Pending IOCs")
    if not results:
        return

    for r in results:
        metrics["ioc_processed"] += 1
        if r["severity"] == "High" or (r.get("corrected") and r["severity"] == "High"):
            high_threat_batch.append(r)

    if len(high_threat_batch) >= 10 or should_send_by_timer(10):
        print("📧 Sending high severity email report...")
        send_batch_email(high_threat_batch)
        metrics["emails_sent"] += 1
        high_threat_batch.clear()

def job_export():
    safe_run(lambda: export_by_severity("High"), "Export High Severity")

def log_metrics():
    print(f"📊 [Metrics] IOCs: {metrics['ioc_processed']}, Emails: {metrics['emails_sent']}, Errors: {metrics['errors_logged']}")
    logging.info(f"📊 Metrics — IOCs: {metrics['ioc_processed']}, Emails: {metrics['emails_sent']}, Errors: {metrics['errors_logged']}")

scheduler = BackgroundScheduler()

scheduler.add_job(job_collect_feeds, 'interval', minutes=10)
scheduler.add_job(job_summarize, 'interval', minutes=5)
scheduler.add_job(job_export, 'interval', minutes=30)
scheduler.add_job(log_metrics, 'interval', minutes=60)

scheduler.start()
print("🟢 Scheduler started. Running threat intelligence pipeline...")

# 🔁 Run each job once immediately
print("⚡ Running all jobs once immediately...\n")
job_collect_feeds()
job_summarize()
job_export()
log_metrics()

logging.info("🕒 Threat Intelligence Pipeline Scheduler started.")
try:
    while True:
        print(f"⏳ Waiting... {datetime.now().strftime('%H:%M:%S')}")
        time.sleep(60)
except (KeyboardInterrupt, SystemExit):
    scheduler.shutdown()
    logging.info("🔴 Scheduler stopped.")
    print("🔴 Scheduler stopped.")
