import os
import json
from pymongo import MongoClient
from dotenv import load_dotenv
import hashlib
from datetime import datetime


load_dotenv()

def hash_ioc(ioc):
    key = f"{ioc.get('type','?')}::{ioc.get('ioc','')}"
    return hashlib.sha256(key.encode()).hexdigest()


def write_iocs_to_mongo(ioc_json_path="data/normalized_iocs.json"):
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

        for ioc in raw_iocs:
            ioc["_id"] = hash_ioc(ioc)  # use hash as unique ID
            ioc["timestamp"] = datetime.utcnow().isoformat()

            try:
                collection.insert_one(ioc)
                inserted_count += 1
            except Exception as insert_error:
                if "duplicate key error" not in str(insert_error):
                    print(f"⚠️ Failed to insert IOC: {insert_error}")

        print(f"✅ {inserted_count} new IOCs inserted into MongoDB")

    except Exception as e:
        print(f"❌ MongoDB insert failed: {e}")

def export_iocs_to_summarizer_input(ioc_json_path="data/normalized_iocs.json", output_txt_path="../threat_model/input.txt"):
    try:
        with open(ioc_json_path, "r") as f:
            iocs = json.load(f)

        # Write all valid non-empty IOCs in format: • type: ioc
        lines = [
            f"• {ioc.get('type', '?')}: {ioc.get('ioc', '').strip()}"
            for ioc in iocs
            if ioc.get("ioc", "").strip()
        ]

        if not lines:
            print("⚠️ No valid IOCs with values found. Nothing written to input.txt.")
            return

        os.makedirs(os.path.dirname(output_txt_path), exist_ok=True)
        with open(output_txt_path, "w") as f:
            f.write("\n".join(lines))

        print(f"✅ {len(lines)} IOCs written to summarizer input: {output_txt_path}")

    except Exception as e:
        print(f"❌ Failed to write IOCs to summarizer input file: {e}")
