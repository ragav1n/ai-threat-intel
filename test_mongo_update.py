import json, hashlib
from pymongo import MongoClient
import datetime

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.threat_intel
collection = db.iocs

def hash_ioc(ioc):
    key = f"{ioc.get('type', '?')}::{ioc.get('ioc', '')}"
    return hashlib.sha256(key.encode()).hexdigest()

ioc = {
    'feed': 'Cisco Security Advisories',
    'ioc': 'CVE-2025-20338',
    'type': 'cve',
    'severity': 'Critical',
    'confidence': 1.0,
    'fused_confidence': 1.0,
    'llm_confidence': None,
    'llm_verified': False,
    'llm_reasoning': '',
    'deobfuscated': False,
}
ioc["_id"] = hash_ioc(ioc)
ioc["ingested_at"] = datetime.datetime.utcnow().isoformat() + "Z"

print("Before Update:", collection.find_one({"_id": ioc["_id"]}))
collection.update_one({"_id": ioc["_id"]}, {"$set": ioc}, upsert=True)
print("After Update:", collection.find_one({"_id": ioc["_id"]}))

