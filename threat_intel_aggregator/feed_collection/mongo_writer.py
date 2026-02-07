"""
MongoDB writer for IOC storage with deduplication.
"""
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

# Use centralized config
try:
    from config import get_config
except ImportError:
    from dotenv import load_dotenv
    import os
    load_dotenv()
    
    # Fallback config
    class FallbackConfig:
        class Mongo:
            uri = os.getenv("MONGO_URI", os.getenv("MONGODB_URI", "mongodb://localhost:27017/"))
            database = os.getenv("MONGO_DB", os.getenv("MONGODB_DB", "threat_intel"))
            ioc_collection = os.getenv("MONGO_IOC_COLLECTION", os.getenv("MONGODB_COLLECTION", "iocs"))
        mongo = Mongo()
    
    def get_config():
        return FallbackConfig()


# Path setup
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

IOC_JSON_PATH = DATA_DIR / "normalized_iocs.json"
SUMMARIZER_INPUT_PATH = BASE_DIR.parent / "threat_model" / "input.txt"


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
            ioc["ingested_at"] = datetime.utcnow().isoformat()

            try:
                collection.insert_one(ioc)
                stats["inserted"] += 1
            except DuplicateKeyError:
                stats["duplicates"] += 1
            except Exception as e:
                print(f"⚠️ Failed to insert IOC: {e}")
                stats["errors"] += 1

        print(f"✅ MongoDB: {stats['inserted']} new, {stats['duplicates']} duplicates, {stats['errors']} errors")
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
