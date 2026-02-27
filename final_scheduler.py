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

def job_detect_campaigns():
    """Phase 3: Run Louvain community detection on the Knowledge Graph."""
    def _detect():
        from threat_intel_aggregator.knowledge_graph.graph_manager import ThreatKnowledgeGraph
        from threat_intel_aggregator.campaign_detector import CampaignDetector
        from threat_intel_aggregator.feed_collection.mongo_writer import write_campaigns_to_mongo

        kg = ThreatKnowledgeGraph(data_dir="data/knowledge_graph", read_only=True)
        detector = CampaignDetector(min_community_size=3, resolution=1.0)
        campaigns = detector.detect(kg)
        kg.close()

        if campaigns:
            stats = write_campaigns_to_mongo(campaigns)
            print(f"🔍 Campaign Detection: {len(campaigns)} campaigns → {stats}")
        else:
            print("🔍 Campaign Detection: No campaigns detected")

        return campaigns

    safe_run(_detect, "Detect Campaigns")

def log_metrics():
    print(f"📊 [Metrics] IOCs: {metrics['ioc_processed']}, Emails: {metrics['emails_sent']}, Errors: {metrics['errors_logged']}")
    logging.info(f"📊 Metrics — IOCs: {metrics['ioc_processed']}, Emails: {metrics['emails_sent']}, Errors: {metrics['errors_logged']}")

def job_predict_ttps():
    """Phase 4: Run agentic TTP prediction for active campaigns."""
    def _predict():
        from threat_intel_aggregator.feed_collection.mongo_writer import (
            get_campaign_collection,
            get_prediction_collection,
            write_prediction_to_mongo,
        )
        from threat_intel_aggregator.predictive_graphrag.graph_traversal import GraphContextRetriever
        from threat_intel_aggregator.predictive_graphrag.ttp_predictor import TTPPredictor
        from datetime import timedelta

        # Only predict for campaigns active in last 48h
        cutoff = (datetime.now() - timedelta(hours=48)).isoformat()
        campaign_coll = get_campaign_collection()
        prediction_coll = get_prediction_collection()

        active_campaigns = list(campaign_coll.find(
            {"last_seen": {"$gte": cutoff}},
            {"_id": 0}
        ).limit(10))

        if not active_campaigns:
            print("🔮 No active campaigns to predict for")
            return []

        # Skip campaigns already predicted today
        today = datetime.now().strftime("%Y-%m-%d")
        retriever = GraphContextRetriever()
        predictor = TTPPredictor()
        results = []

        for campaign in active_campaigns:
            cid = campaign.get("campaign_id", "")
            existing = prediction_coll.find_one({
                "campaign_id": cid,
                "generated_at": {"$regex": f"^{today}"}
            })
            if existing:
                continue

            try:
                context = retriever.retrieve_campaign_context(campaign)
                prediction = predictor.predict(context)
                write_prediction_to_mongo(prediction)
                results.append(prediction)
                print(f"🔮 Predicted TTPs for {campaign.get('label', cid)}")
            except Exception as e:
                logging.error(f"❌ Prediction failed for {cid}: {e}")

        retriever.close()
        print(f"🔮 TTP Prediction complete: {len(results)} new predictions")
        return results

    safe_run(_predict, "Predict TTPs")

def job_run_evaluation():
    """Phase 5: Run extraction evaluation against ground-truth dataset."""
    def _evaluate():
        from threat_intel_aggregator.evaluation.evaluator import Evaluator

        evaluator = Evaluator(min_confidence=0.0)
        report = evaluator.run(run_benchmark=True)

        try:
            evaluator.save_report(report)
        except Exception as e:
            logging.warning(f"⚠️ Evaluation persistence skipped: {e}")

        print(
            f"📏 Evaluation: P={report.metrics.precision:.3f} "
            f"R={report.metrics.recall:.3f} F1={report.metrics.f1:.3f} "
            f"({report.metrics.true_positives} TP, "
            f"{report.metrics.false_positives} FP, "
            f"{report.metrics.false_negatives} FN)"
        )
        return report

    safe_run(_evaluate, "Run Evaluation")

scheduler = BackgroundScheduler()

scheduler.add_job(job_collect_feeds, 'interval', minutes=10)
scheduler.add_job(job_summarize, 'interval', minutes=5)
scheduler.add_job(job_export, 'interval', minutes=30)
scheduler.add_job(job_detect_campaigns, 'interval', minutes=30)
scheduler.add_job(job_predict_ttps, 'interval', minutes=60)
scheduler.add_job(job_run_evaluation, 'interval', hours=6)
scheduler.add_job(log_metrics, 'interval', minutes=60)

scheduler.start()
print("🟢 Scheduler started. Running threat intelligence pipeline...")

# 🔁 Run each job once immediately
print("⚡ Running all jobs once immediately...\n")
job_collect_feeds()
job_summarize()
job_export()
job_detect_campaigns()
job_predict_ttps()
job_run_evaluation()
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

