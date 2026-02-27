"""
Data models for Predictive GraphRAG TTP forecasting.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone


@dataclass
class CampaignContext:
    """Rich context retrieved from the Knowledge Graph + campaigns for prediction."""

    campaign_id: str
    campaign_label: str
    ioc_members: List[str]
    temporal: Dict[str, Any] = field(default_factory=dict)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    type_distribution: Dict[str, int] = field(default_factory=dict)
    graph_neighbors: Dict[str, List[str]] = field(default_factory=dict)
    mitre_context: List[Dict[str, Any]] = field(default_factory=list)
    campaign_profile: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PredictedTTP:
    """A single predicted next MITRE ATT&CK technique."""

    tactic: str               # e.g. "Lateral Movement"
    technique_id: str          # e.g. "T1021"
    technique_name: str        # e.g. "Remote Services"
    confidence: float          # 0.0–1.0
    reasoning: str = ""

    def __post_init__(self):
        self.confidence = max(0.0, min(1.0, self.confidence))

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TTPPrediction:
    """Full prediction result for a campaign."""

    campaign_id: str
    campaign_label: str
    current_stage: str                           # Kill chain stage classification
    predictions: List[PredictedTTP]              # Top-N next likely TTPs
    defensive_recommendations: List[str] = field(default_factory=list)
    model_used: str = "qwen2.5:7b"
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["_id"] = f"pred_{self.campaign_id}_{self.generated_at[:10]}"
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "TTPPrediction":
        """Reconstruct from a MongoDB document."""
        data.pop("_id", None)
        preds = [PredictedTTP(**p) for p in data.pop("predictions", [])]
        return cls(predictions=preds, **{
            k: v for k, v in data.items()
            if k in cls.__dataclass_fields__
        })
