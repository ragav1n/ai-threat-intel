import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# -------------------------
# Path setup
# -------------------------
BASE_DIR = Path(__file__).resolve().parent.parent  # points to threat_intel_aggregator/
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

IOC_JSON_PATH = DATA_DIR / "normalized_iocs.json"
SUMMARIZER_INPUT_PATH = BASE_DIR.parent / "threat_model" / "input.txt"


def hash_ioc(ioc):
    key = f"{ioc.get('type','?')}::{ioc.get('ioc','')}"
    return hashlib.sha256(key.encode()).hexdigest()


def write_iocs_to_mongo(ioc_json_path=IOC_JSON_PATH):
    try:
        uri = os.getenv("MONGODB_URI")
        db_name = os.getenv("MONGODB_DB", "threat_intel")
        collection_name = os.getenv("MONGODB_COLLECTION", "iocs")

        if not uri:
            raise ValueError("MONGODB_URI not set in .env")

        client = MongoClient(uri)
        db = client[db_name]
        collection = db[collection_name]

        with open(ioc_json_path, "r") as f:
            raw_iocs = json.load(f)

        if not isinstance(raw_iocs, list):
            raise ValueError("Expected a list of IOCs in JSON")

        inserted_count = 0

        duplicate_count = 0

        for ioc in raw_iocs:
            ioc["_id"] = hash_ioc(ioc)  # use hash as unique ID
            ioc["timestamp"] = datetime.utcnow().isoformat()

            try:
                collection.insert_one(ioc)
                inserted_count += 1
            except Exception as insert_error:
                if "duplicate key error" in str(insert_error):
                    duplicate_count += 1
                else:
                    print(f"⚠️ Failed to insert IOC: {insert_error}")

        print(f"✅ {inserted_count} new IOCs inserted into MongoDB")
        print(f"♻️  {duplicate_count} duplicate IOCs skipped")

    except Exception as e:
        print(f"❌ MongoDB insert failed: {e}")


def export_iocs_to_summarizer_input(ioc_json_path=IOC_JSON_PATH, output_txt_path=SUMMARIZER_INPUT_PATH):
    try:
        with open(ioc_json_path, "r") as f:
            iocs = json.load(f)

        lines = [
            f"• {ioc.get('type', '?')}: {ioc.get('ioc', '').strip()}"
            for ioc in iocs
            if ioc.get("ioc", "").strip()
        ]

        if not lines:
            print("⚠️ No valid IOCs with values found. Nothing written to input.txt.")
            return

        output_txt_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_txt_path, "w") as f:
            f.write("\n".join(lines))

        print(f"✅ {len(lines)} IOCs written to summarizer input: {output_txt_path}")

    except Exception as e:
        print(f"❌ Failed to write IOCs to summarizer input file: {e}")
