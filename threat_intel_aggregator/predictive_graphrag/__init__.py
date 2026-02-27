"""
Phase 4: Agentic Predictive GraphRAG — Threat Forecasting.

Predicts the next most likely MITRE ATT&CK Tactic a campaign will execute
by traversing the Knowledge Graph and using a multi-step agentic LLM pipeline.
"""
from .graph_traversal import GraphContextRetriever
from .ttp_predictor import TTPPredictor
from .models import TTPPrediction, PredictedTTP, CampaignContext
