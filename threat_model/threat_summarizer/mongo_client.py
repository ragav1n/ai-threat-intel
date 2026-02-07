"""
MongoDB client for storing threat summaries.
Uses lazy initialization to avoid crashes on import.
"""
import os
from typing import Optional, Dict, Any

from pymongo import MongoClient
from pymongo.collection import Collection
from dotenv import load_dotenv


# Load environment variables
load_dotenv()


# MongoDB configuration
MONGO_URI = os.getenv("MONGO_URI", os.getenv("MONGODB_URI"))
MONGO_DB = os.getenv("MONGO_DB", os.getenv("MONGODB_DB", "threat_intel"))
MONGO_COLLECTION = os.getenv("MONGO_SUMMARY_COLLECTION", "threat_summaries")


# Lazy-initialized client singleton
_client: Optional[MongoClient] = None


def get_client() -> Optional[MongoClient]:
    """Get or create MongoDB client singleton."""
    global _client
    
    if _client is None:
        if not MONGO_URI:
            return None
        _client = MongoClient(MONGO_URI)
    
    return _client


def get_collection() -> Optional[Collection]:
    """Get the threat summaries collection."""
    client = get_client()
    if client is None:
        return None
    
    db = client[MONGO_DB]
    return db[MONGO_COLLECTION]


def upload_summary(entry: Dict[str, Any]) -> bool:
    """
    Upload a threat summary to MongoDB.
    
    Args:
        entry: The summary dictionary to upload.
        
    Returns:
        True if upload succeeded, False otherwise.
    """
    collection = get_collection()
    if collection is None:
        # MongoDB not configured - silently skip
        return False
    
    try:
        collection.insert_one(entry)
        return True
    except Exception as e:
        print(f"[⚠️ MongoDB Upload Failed] {e}")
        return False


def get_summary_count() -> int:
    """Get the total number of stored summaries."""
    collection = get_collection()
    if collection is None:
        return 0
    
    try:
        return collection.count_documents({})
    except Exception:
        return 0


def get_recent_summaries(limit: int = 10) -> list[Dict[str, Any]]:
    """Get the most recent summaries."""
    collection = get_collection()
    if collection is None:
        return []
    
    try:
        return list(
            collection.find()
            .sort("timestamp", -1)
            .limit(limit)
        )
    except Exception:
        return []
