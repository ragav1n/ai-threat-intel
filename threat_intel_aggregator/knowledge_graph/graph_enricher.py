import hashlib
from typing import List, Dict, Any

def generate_entry_id(url: str, title: str) -> str:
    """Generates a stable SHA256 hash for a feed entry."""
    unique_str = f"{url}|{title}"
    return hashlib.sha256(unique_str.encode()).hexdigest()

def enrich_co_occurrence(kg, iocs_in_entry: List[Dict[str, Any]], entry_id: str):
    """
    Creates CO_OCCURS_WITH edges between all IOCs found in the same article.
    This logic is typically called via the graph manager's update_from_batch.
    """
    # This is a placeholder for more complex enrichment logic 
    # (e.g. NLP-based relationship extraction) in the future.
    # For now, it's handled by the manager's clique logic.
    pass
