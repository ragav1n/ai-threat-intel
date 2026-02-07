"""
Configuration settings for the AI Threat Intelligence system.
"""
import os
from pathlib import Path

# Base Paths (Relative to project root)
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "threat_intel_aggregator" / "data"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Database Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/")
MONGO_DB = os.getenv("MONGO_DB", "threat_intel")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "summaries")

# Secrets
TRIGGER_SECRET = os.getenv("TRIGGER_SECRET", "socgen-feed-key")

# Scheduler
SCHEDULER_INTERVAL_MINUTES = int(os.getenv("SCHEDULER_INTERVAL", "10"))

# AI Configuration
OLLAMA_BASE_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
OLLAMA_TIMEOUT = 120  # seconds

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = BASE_DIR / "threat_model" / "logs" / "threat_intel.log"

# Create log directory
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
