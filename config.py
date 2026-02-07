"""
Centralized configuration management for AI Threat Intel.

Loads all configuration from environment variables with sensible defaults.
"""
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

from dotenv import load_dotenv

# Load .env file
load_dotenv()


@dataclass
class MongoConfig:
    """MongoDB configuration."""
    uri: str
    database: str
    ioc_collection: str
    summary_collection: str
    
    @property
    def full_uri(self) -> str:
        """Get the full MongoDB URI."""
        return self.uri


@dataclass
class AppConfig:
    """Application configuration."""
    debug: bool
    log_level: str
    api_host: str
    api_port: int
    scheduler_interval_minutes: int
    

@dataclass
class Config:
    """Root configuration container."""
    mongo: MongoConfig
    app: AppConfig


@lru_cache()
def get_config() -> Config:
    """
    Get the application configuration.
    
    Uses lru_cache to ensure config is only loaded once.
    """
    return Config(
        mongo=MongoConfig(
            uri=os.getenv("MONGO_URI", "mongodb://localhost:27017/"),
            database=os.getenv("MONGO_DB", "threat_intel"),
            ioc_collection=os.getenv("MONGO_IOC_COLLECTION", "iocs"),
            summary_collection=os.getenv("MONGO_COLLECTION", "summaries"),
        ),
        app=AppConfig(
            debug=os.getenv("DEBUG", "false").lower() == "true",
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            api_host=os.getenv("API_HOST", "0.0.0.0"),
            api_port=int(os.getenv("API_PORT", "8000")),
            scheduler_interval_minutes=int(os.getenv("SCHEDULER_INTERVAL", "10")),
        ),
    )


# Convenience function for quick access
def get_mongo_uri() -> str:
    """Get MongoDB URI."""
    return get_config().mongo.uri


def get_mongo_db() -> str:
    """Get MongoDB database name."""
    return get_config().mongo.database
