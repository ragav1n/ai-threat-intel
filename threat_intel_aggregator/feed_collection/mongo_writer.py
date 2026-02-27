"""
MongoDB writer for IOC storage with deduplication.
"""
import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

# Use centralized config
from pathlib import Path
try:
    import sys
    # Add root to path if needed for config import
    root_path = Path(__file__).resolve().parent.parent.parent
    if str(root_path) not in sys.path:
        sys.path.append(str(root_path))
    from config import get_config, DATA_DIR, BASE_DIR as ROOT_BASE_DIR
except ImportError:
    ROOT_BASE_DIR = Path(__file__).resolve().parent.parent.parent
    # Check for volume mount first, same as root config.py
    if os.path.exists("/app/data"):
        DATA_DIR = Path("/app/data")
    else:
        DATA_DIR = ROOT_BASE_DIR / "data"
        
    from dotenv import load_dotenv
    import os
    load_dotenv()
    
    class FallbackConfig:
        class Mongo:
            uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
            database = os.getenv("MONGO_DB", "threat_intel")
            ioc_collection = os.getenv("MONGO_IOC_COLLECTION", "iocs")
        mongo = Mongo()
    
    def get_config():
        return FallbackConfig()


# Path setup
IOC_JSON_PATH = DATA_DIR / "normalized_iocs.json"
SUMMARIZER_INPUT_PATH = ROOT_BASE_DIR.parent / "threat_model" / "input.txt"


# MongoDB connection singleton
_mongo_client: Optional[MongoClient] = None


def get_mongo_client() -> MongoClient:
    """Get or create MongoDB client singleton."""
    global _mongo_client
    if _mongo_client is None:
        config = get_config()
        _mongo_client = MongoClient(config.mongo.uri)
    return _mongo_client


def get_ioc_collection():
    """Get the IOC collection from MongoDB."""
    config = get_config()
    client = get_mongo_client()
    db = client[config.mongo.database]
    return db[config.mongo.ioc_collection]


def hash_ioc(ioc: Dict[str, Any]) -> str:
    """Generate unique hash for an IOC based on type and value."""
    key = f"{ioc.get('type', '?')}::{ioc.get('ioc', '')}"
    return hashlib.sha256(key.encode()).hexdigest()


def write_iocs_to_mongo(ioc_json_path: Path = IOC_JSON_PATH) -> Dict[str, int]:
    """
    Write IOCs to MongoDB with deduplication.
    
    Args:
        ioc_json_path: Path to the normalized IOCs JSON file.
        
    Returns:
        Dictionary with insert/duplicate/error counts.
    """
    stats = {"inserted": 0, "duplicates": 0, "errors": 0}
    
    try:
        collection = get_ioc_collection()
        
        with open(ioc_json_path, "r") as f:
            raw_iocs = json.load(f)

        if not isinstance(raw_iocs, list):
            raise ValueError("Expected a list of IOCs in JSON")

        for ioc in raw_iocs:
            ioc["_id"] = hash_ioc(ioc)
            ioc["ingested_at"] = datetime.utcnow().isoformat() + "Z"
            
            # Ensure Phase 1 fields have defaults if missing
            ioc.setdefault("fused_confidence", ioc.get("confidence", 0.5))
            ioc.setdefault("llm_verified", False)
            ioc.setdefault("llm_confidence", None)
            ioc.setdefault("llm_reasoning", "")
            ioc.setdefault("deobfuscated", False)

        from pymongo import UpdateOne
        
        operations = []
        for ioc in raw_iocs:
            ioc["_id"] = hash_ioc(ioc)
            ioc["ingested_at"] = datetime.utcnow().isoformat() + "Z"
            
            # Ensure Phase 1 fields have defaults if missing
            ioc.setdefault("fused_confidence", ioc.get("confidence", 0.5))
            ioc.setdefault("llm_verified", False)
            ioc.setdefault("llm_confidence", None)
            ioc.setdefault("llm_reasoning", "")
            ioc.setdefault("deobfuscated", False)

            operations.append(
                UpdateOne({"_id": ioc["_id"]}, {"$set": ioc}, upsert=True)
            )

        if operations:
            result = collection.bulk_write(operations, ordered=False)
            stats["inserted"] = result.upserted_count + result.modified_count
        
        print(f"✅ MongoDB Bulk Write: {stats['inserted']} records processed")
        return stats

    except FileNotFoundError:
        print("❌ No IOC file found to write to MongoDB")
        return stats
    except Exception as e:
        print(f"❌ MongoDB write failed: {e}")
        return stats


def export_iocs_to_summarizer_input(
    ioc_json_path: Path = IOC_JSON_PATH,
    output_txt_path: Path = SUMMARIZER_INPUT_PATH,
    max_iocs: int = 500
) -> int:
    """
    Export IOCs to the summarizer input file.
    
    Args:
        ioc_json_path: Path to the IOC JSON file.
        output_txt_path: Path to write the summarizer input.
        max_iocs: Maximum number of IOCs to export.
        
    Returns:
        Number of IOCs written.
    """
    try:
        with open(ioc_json_path, "r") as f:
            iocs = json.load(f)

        # Limit and format IOCs
        lines = [
            f"• {ioc.get('type', '?')}: {ioc.get('ioc', '').strip()}"
            for ioc in iocs[:max_iocs]
            if ioc.get("ioc", "").strip()
        ]

        if not lines:
            print("⚠️ No valid IOCs to write to summarizer input.")
            return 0

        output_txt_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_txt_path, "w") as f:
            f.write("\n".join(lines))

        print(f"✅ {len(lines)} IOCs written to summarizer input")
        return len(lines)

    except FileNotFoundError:
        print("❌ No IOC file found to export")
        return 0
    except Exception as e:
        print(f"❌ Failed to write summarizer input: {e}")
        return 0


def get_ioc_stats() -> Dict[str, Any]:
    """Get statistics about stored IOCs from MongoDB."""
    try:
        collection = get_ioc_collection()
        
        total = collection.count_documents({})
        by_type = list(collection.aggregate([
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]))
        by_severity = list(collection.aggregate([
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]))
        
        return {
            "total": total,
            "by_type": {item["_id"]: item["count"] for item in by_type},
            "by_severity": {item["_id"]: item["count"] for item in by_severity},
        }
    except Exception as e:
        print(f"❌ Failed to get IOC stats: {e}")
        return {"total": 0, "by_type": {}, "by_severity": {}}


# ----------- Campaign Persistence -----------


def get_campaign_collection():
    """Get the campaigns collection from MongoDB."""
    config = get_config()
    client = get_mongo_client()
    db = client[config.mongo.database]
    return db["campaigns"]


def write_campaigns_to_mongo(campaigns) -> Dict[str, int]:
    """
    Write detected campaigns to MongoDB with upsert.

    Args:
        campaigns: List of Campaign objects (from campaign_detector.models).

    Returns:
        Dictionary with upserted/error counts.
    """
    from pymongo import UpdateOne

    stats = {"upserted": 0, "errors": 0}

    try:
        collection = get_campaign_collection()

        operations = []
        for campaign in campaigns:
            doc = campaign.to_dict()
            operations.append(
                UpdateOne({"_id": doc["_id"]}, {"$set": doc}, upsert=True)
            )

        if operations:
            result = collection.bulk_write(operations, ordered=False)
            stats["upserted"] = result.upserted_count + result.modified_count

        print(f"✅ Campaigns persisted: {stats['upserted']} records")
        return stats

    except Exception as e:
        print(f"❌ Campaign write failed: {e}")
        stats["errors"] += 1
        return stats


# ----------- Prediction Persistence (Phase 4) -----------


def get_prediction_collection():
    """Get the predictions collection from MongoDB."""
    config = get_config()
    client = get_mongo_client()
    db = client[config.mongo.database]
    return db["predictions"]


def write_prediction_to_mongo(prediction) -> dict:
    """
    Write a TTP prediction to MongoDB.

    Args:
        prediction: TTPPrediction object (from predictive_graphrag.models).

    Returns:
        Dictionary with upserted status.
    """
    from pymongo import UpdateOne

    try:
        collection = get_prediction_collection()
        doc = prediction.to_dict()

        result = collection.update_one(
            {"_id": doc["_id"]},
            {"$set": doc},
            upsert=True,
        )

        status = "upserted" if result.upserted_id else "updated"
        print(f"✅ Prediction persisted: {status}")
        return {"status": status, "id": doc["_id"]}

    except Exception as e:
        print(f"❌ Prediction write failed: {e}")
        return {"status": "error", "error": str(e)}


