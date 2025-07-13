import os
from pymongo import MongoClient
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB", "threat_intel_db")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "threat_summaries")

if not MONGO_URI:
    raise RuntimeError("❌ MONGO_URI not found in .env file.")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
collection = db[MONGO_COLLECTION]

def upload_summary(entry: dict):
    collection.insert_one(entry)
