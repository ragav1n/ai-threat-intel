"""
Phase 3: Temporal Campaign Detection.

Detects coordinated threat campaigns by applying community detection
algorithms to the Knowledge Graph and analyzing IOC temporal patterns.
"""
from .detector import CampaignDetector

__all__ = ["CampaignDetector"]
