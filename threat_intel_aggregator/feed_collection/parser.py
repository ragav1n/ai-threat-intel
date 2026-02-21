"""
Feed content parsing and IOC normalization.
Enhanced with confidence scoring.
"""
import json
import csv
import os
import logging
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Union

import feedparser
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_fixed

from .ioc_extractor import extract_iocs_with_confidence, IOCMatch
from .config import RAW_FEED_OUTPUT, NORMALIZED_IOC_JSON, NORMALIZED_IOC_CSV
from .llm_ioc_verifier import get_llm_verifier
from .confidence_fusion import fuse_confidence, fuse_with_penalty

# Import enums
try:
    from threat_intel_aggregator.enums import IOCType, Severity
except ImportError:
    from ..enums import IOCType, Severity

logger = logging.getLogger(__name__)

# Severity mapping based on IOC type
IOC_SEVERITY_MAP: Dict[IOCType, Severity] = {
    IOCType.IP: Severity.MEDIUM,
    IOCType.IPV6: Severity.MEDIUM,
    IOCType.DOMAIN: Severity.MEDIUM,
    IOCType.URL: Severity.HIGH,
    IOCType.MD5: Severity.HIGH,
    IOCType.SHA1: Severity.HIGH,
    IOCType.SHA256: Severity.HIGH,
    IOCType.EMAIL: Severity.LOW,
    IOCType.CVE: Severity.CRITICAL,
}


def get_severity_for_ioc(ioc_type: Union[IOCType, str], confidence: float = 0.5) -> Severity:
    """
    Get the severity level for a given IOC type, adjusted by confidence.
    
    High confidence (>0.8) can elevate severity.
    Low confidence (<0.4) can reduce severity.
    """
    # Normalize ioc_type to Enum if it's a string
    if isinstance(ioc_type, str):
        try:
            ioc_type = IOCType.from_string(ioc_type)
        except ValueError:
            # Fallback for manual string comparison if Enum fails
            if ioc_type.lower() == "cve":
                return Severity.CRITICAL
            return Severity.UNKNOWN

    base_severity = IOC_SEVERITY_MAP.get(ioc_type, Severity.UNKNOWN)
    
    # Adjust severity based on confidence
    if confidence >= 0.85:
        # Elevate if not already CRITICAL
        if base_severity == Severity.HIGH:
            return Severity.CRITICAL
        elif base_severity == Severity.MEDIUM:
            return Severity.HIGH
    elif confidence < 0.4:
        # Reduce severity for low confidence
        if base_severity == Severity.CRITICAL:
            return Severity.HIGH
        elif base_severity == Severity.HIGH:
            return Severity.MEDIUM
        elif base_severity == Severity.MEDIUM:
            return Severity.LOW
    
    return base_severity


def generate_entry_id(url: str, title: str) -> str:
    """Generates a stable SHA256 hash for a feed entry."""
    unique_str = f"{url}|{title}"
    return hashlib.sha256(unique_str.encode()).hexdigest()


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def parse_feeds(url: str) -> List[Dict[str, Any]]:
    """
    Parse RSS/Atom feed from URL with retry logic.
    
    Args:
        url: Feed URL to parse.
        
    Returns:
        List of parsed feed entries.
    """
    print(f"🔄 Trying to fetch: {url}")
    feed = feedparser.parse(url)

    if not feed.entries:
        raise ValueError(f"No entries found for {url}")

    entries = []
    for entry in feed.entries:
        entries.append({
            "source": feed.feed.get("title", "Unknown Source"),
            "title": entry.get("title", ""),
            "link": entry.get("link", ""),
            "summary": entry.get("summary", ""),
            "published": entry.get("published", ""),
            "feed_url": url
        })

    return entries


def normalize_and_store_iocs(
    feed_name: str, 
    text: str, 
    source_url: str, 
    timestamp: str,
    source_reliability: float = 1.0,
    min_confidence: float = 0.3,
    enable_llm_verification: bool = True,
    max_llm_verify: int = 5,  # Reduced from 50 to prevent pipeline stalls
) -> List[Dict[str, Any]]:
    """
    Extract and normalize IOCs from text content with hybrid confidence scoring.
    
    Pipeline: Regex extraction → LLM verification → Confidence fusion.
    
    Args:
        feed_name: Name of the source feed.
        text: Text content to extract IOCs from.
        source_url: URL of the source.
        timestamp: ISO timestamp of extraction.
        min_confidence: Minimum confidence threshold.
        enable_llm_verification: Whether to run LLM verification pass.
        max_llm_verify: Max IOCs to verify via LLM per batch.
        
    Returns:
        List of normalized IOC entries with fused confidence scores.
    """
    # Step 1: Regex extraction (with deobfuscation built-in)
    ioc_matches = extract_iocs_with_confidence(text, min_confidence=min_confidence)
    
    if not ioc_matches:
        return []
    
    # Step 2: LLM verification pass (optional, with graceful fallback)
    llm_results = {}
    if enable_llm_verification:
        try:
            # ONLY verify high-value or highly suspicious IOCs via LLM to save time
            high_value_matches = [
                m for m in ioc_matches 
                if m.ioc_type in [IOCType.CVE, IOCType.URL, IOCType.IP] and m.confidence > 0.6
            ][:max_llm_verify]
            
            if high_value_matches:
                verifier = get_llm_verifier()
                if verifier.is_available():
                    verified = verifier.batch_verify(high_value_matches, max_iocs=max_llm_verify)
                    llm_results = {v["ioc"]: v for v in verified}
                    logger.info(f"🤖 LLM verified {len(llm_results)} high-value IOCs for [{feed_name}]")
                else:
                    logger.warning(f"⚠️ LLM unavailable, using regex-only confidence for [{feed_name}]")
        except Exception as e:
            logger.error(f"❌ LLM verification failed for [{feed_name}]: {e}")
    
    # Step 3: Confidence fusion and normalization
    normalized_entries = []
    for match in ioc_matches:
        llm_data = llm_results.get(match.value, {})
        llm_confidence = llm_data.get("llm_confidence")
        llm_is_valid = llm_data.get("is_valid_ioc", True)
        llm_verified = llm_data.get("llm_verified", False)
        llm_reasoning = llm_data.get("llm_reasoning", "")
        
        # Fuse confidence scores with penalty for invalid IOCs
        fused = fuse_with_penalty(
            regex_confidence=match.confidence,
            llm_confidence=llm_confidence,
            llm_is_valid=llm_is_valid,
            source_reliability=source_reliability,
        )
        
        # Use fused confidence for severity calculation
        severity = get_severity_for_ioc(match.ioc_type, fused)
        
        entry = {
            "feed": feed_name,
            "ioc": match.value,
            "type": str(match.ioc_type),
            "severity": str(severity),
            "confidence": round(match.confidence, 4),
            "fused_confidence": round(fused, 4),
            "llm_confidence": round(llm_confidence, 4) if llm_confidence is not None else None,
            "llm_verified": llm_verified,
            "llm_reasoning": llm_reasoning,
            "deobfuscated": getattr(match, 'deobfuscated', False),
            "timestamp": timestamp,
            "source_url": source_url,
        }
        normalized_entries.append(entry)

    return normalized_entries


def normalize_parsed_results(min_confidence: float = 0.3, kg_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
    """
    Process raw feed data and extract normalized IOCs with confidence scores.
    
    Args:
        min_confidence: Minimum confidence threshold for IOCs.
        kg_callback: Optional callback to update knowledge graph (List[IOC], context_id).
    
    Returns:
        List of all normalized IOC entries.
    """
    if not os.path.exists(RAW_FEED_OUTPUT):
        print("❌ No raw feed output to normalize.")
        return []

    with open(RAW_FEED_OUTPUT) as f:
        raw_data = json.load(f)

    normalized: List[Dict[str, Any]] = []
    now = datetime.utcnow().isoformat() + "Z"

    for feed_name, data in raw_data.items():
        if data.get("status") != "success":
            continue

        raw_content = data.get("content", "")
        source_url = data.get("url", "")
        source_reliability = data.get("reliability", 0.5)
        
        # Check if it's a feed (RSS/Atom)
        is_rss = False
        parsed_feed = None
        content_stripped = str(raw_content).strip()
        
        # Only parse if it looks like XML, to avoid feedparser downloading raw URLs
        if content_stripped.startswith("<") or "<?xml" in content_stripped[:100]:
            try:
                parsed_feed = feedparser.parse(raw_content)
                if hasattr(parsed_feed, 'entries') and parsed_feed.entries:
                    is_rss = True
            except Exception as e:
                logger.warning(f"Failed to parse feed {feed_name}: {e}")
        
        if is_rss and parsed_feed:
            # RSS/Atom feed detected - process individual entries
            for entry in parsed_feed.entries:
                title = entry.get("title", "")
                summary = entry.get("summary", "")
                entry_text = f"{title} {summary}"
                entry_url = entry.get("link", source_url)
                entry_id = generate_entry_id(entry_url, title)
                
                found_iocs = normalize_and_store_iocs(
                    feed_name=feed_name,
                    text=entry_text,
                    source_url=entry_url,
                    timestamp=now,
                    source_reliability=source_reliability,
                    min_confidence=min_confidence
                )
                
                if found_iocs:
                    if kg_callback:
                        kg_callback(found_iocs, entry_id)
                    normalized.extend(found_iocs)
        else:
            # Simple HTML or plaintext
            soup = BeautifulSoup(raw_content, "html.parser")
            clean_text = soup.get_text(separator=" ")
            entry_id = generate_entry_id(source_url, feed_name)

            found_iocs = normalize_and_store_iocs(
                feed_name=feed_name,
                text=clean_text,
                source_url=source_url,
                timestamp=now,
                source_reliability=source_reliability,
                min_confidence=min_confidence
            )

            if found_iocs:
                if kg_callback:
                    kg_callback(found_iocs, entry_id)
                normalized.extend(found_iocs)

    # Save to JSON (includes confidence field)
    try:
        with open(NORMALIZED_IOC_JSON, "w") as f:
            json.dump(normalized, f, indent=2)
    except Exception as e:
        print(f"❌ Failed to write normalized_iocs.json: {e}")

    # Save to CSV (includes confidence field)
    try:
        with open(NORMALIZED_IOC_CSV, "w", newline="") as csvfile:
            fieldnames = ["feed", "ioc", "type", "severity", "confidence", "fused_confidence", "llm_confidence", "llm_verified", "llm_reasoning", "deobfuscated", "timestamp", "source_url"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in normalized:
                writer.writerow(row)
    except Exception as e:
        print(f"❌ Failed to write normalized_iocs.csv: {e}")

    print(f"\n📁 Saved {len(normalized)} normalized IOCs.")
    return normalized
