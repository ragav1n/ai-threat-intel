"""
MongoDB Client for Threat Summarizer.
Handles connection and operations for summaries and IOCs.
"""
import os
from pymongo import MongoClient
from typing import Optional, Dict, Any

# Environment variables
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = os.getenv("MONGO_DB", "threat_intel")
SUMMARY_COLLECTION = "threat_summaries"
IOC_COLLECTION = "iocs"

_client: Optional[MongoClient] = None

def get_client() -> MongoClient:
    """Get or create a MongoDB client instance."""
    global _client
    if _client is None:
        try:
            _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            # Trigger connection check
            _client.server_info()
            print(f"✅ Connected to MongoDB at {MONGO_URI}")
        except Exception as e:
            print(f"❌ Failed to connect to MongoDB: {e}")
            _client = None
    return _client

def get_collection():
    """Get the threat summaries collection."""
    client = get_client()
    if client:
        return client[MONGO_DB][SUMMARY_COLLECTION]
    return None

def get_ioc_collection():
    """Get the IOC collection."""
    client = get_client()
    if client:
        return client[MONGO_DB][IOC_COLLECTION]
    return None

def upload_summary(summary_data: Dict[str, Any]) -> bool:
    """
    Upload a threat summary to MongoDB.
    
    Args:
        summary_data: Dictionary containing summary details.
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        collection = get_collection()
        if collection is None:
            return False
            
        result = collection.insert_one(summary_data)
        print(f"✅ Summary uploaded with ID: {result.inserted_id}")
        return True
    except Exception as e:
        print(f"❌ Failed to upload summary: {e}")
        return False

def upload_ioc(ioc_data: Dict[str, Any]) -> bool:
    """
    Upload an IOC to MongoDB.
    
    Args:
        ioc_data: Dictionary containing IOC details.
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        collection = get_ioc_collection()
        if collection is None:
            return False
        
        # Insert with deduplication check if needed, but for now simple insert
        # The API server seems to rely on this or expects it to handle simple storage
        # Ideally we check for duplicates, but let's stick to basic insert for now
        # or use update_one with upsert if we have a unique key.
        # Based on file analysis, let's just insert.
        
        result = collection.insert_one(ioc_data)
        # print(f"✅ IOC uploaded: {ioc_data.get('ioc')}")
        return True
    except Exception as e:
        print(f"❌ Failed to upload IOC: {e}")
        return False
