"""
Tests for Phase 4: Agentic Predictive GraphRAG — TTP Forecasting.

Tests cover:
  - Data models (CampaignContext, PredictedTTP, TTPPrediction)
  - Graph traversal (context retrieval, profile building)
  - TTP predictor (JSON extraction, fallback predictions, stage classification parsing)
  - Integration (full predict pipeline with mock LLM)
"""
import pytest
import json
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

# ---------- Model Tests ----------

from threat_intel_aggregator.predictive_graphrag.models import (
    CampaignContext,
    PredictedTTP,
    TTPPrediction,
)


class TestPredictedTTP:
    """Tests for PredictedTTP model."""

    def test_confidence_clamping_high(self):
        ttp = PredictedTTP(
            tactic="Lateral Movement",
            technique_id="T1021",
            technique_name="Remote Services",
            confidence=1.5,
        )
        assert ttp.confidence == 1.0

    def test_confidence_clamping_low(self):
        ttp = PredictedTTP(
            tactic="Exfiltration",
            technique_id="T1041",
            technique_name="Exfiltration Over C2",
            confidence=-0.3,
        )
        assert ttp.confidence == 0.0

    def test_to_dict(self):
        ttp = PredictedTTP(
            tactic="Discovery",
            technique_id="T1083",
            technique_name="File Discovery",
            confidence=0.75,
            reasoning="High file hash activity",
        )
        d = ttp.to_dict()
        assert d["tactic"] == "Discovery"
        assert d["technique_id"] == "T1083"
        assert d["confidence"] == 0.75

    def test_normal_confidence(self):
        ttp = PredictedTTP(
            tactic="Execution",
            technique_id="T1059",
            technique_name="Command Scripting",
            confidence=0.65,
        )
        assert ttp.confidence == 0.65


class TestTTPPrediction:
    """Tests for TTPPrediction model."""

    def test_auto_timestamp(self):
        pred = TTPPrediction(
            campaign_id="test_123",
            campaign_label="Test Campaign",
            current_stage="Reconnaissance",
            predictions=[],
        )
        assert pred.generated_at != ""
        # Should be parseable as ISO format
        datetime.fromisoformat(pred.generated_at.replace("Z", "+00:00"))

    def test_to_dict_has_id(self):
        pred = TTPPrediction(
            campaign_id="campaign_abc",
            campaign_label="Test",
            current_stage="Initial Access",
            predictions=[
                PredictedTTP(
                    tactic="Execution",
                    technique_id="T1059",
                    technique_name="Scripts",
                    confidence=0.8,
                )
            ],
            generated_at="2026-02-27T00:00:00+00:00",
        )
        d = pred.to_dict()
        assert "_id" in d
        assert d["_id"].startswith("pred_campaign_abc_")
        assert d["campaign_id"] == "campaign_abc"
        assert len(d["predictions"]) == 1

    def test_from_dict_round_trip(self):
        original = TTPPrediction(
            campaign_id="rt_test",
            campaign_label="Round Trip",
            current_stage="Command and Control",
            predictions=[
                PredictedTTP(
                    tactic="Exfiltration",
                    technique_id="T1041",
                    technique_name="Exfiltration Over C2",
                    confidence=0.7,
                    reasoning="C2 stage leads to exfiltration",
                )
            ],
            defensive_recommendations=["Monitor outbound traffic"],
            generated_at="2026-01-01T00:00:00+00:00",
        )
        d = original.to_dict()
        restored = TTPPrediction.from_dict(d)
        assert restored.campaign_id == "rt_test"
        assert restored.current_stage == "Command and Control"
        assert len(restored.predictions) == 1
        assert restored.predictions[0].tactic == "Exfiltration"
        assert restored.defensive_recommendations == ["Monitor outbound traffic"]


class TestCampaignContext:
    """Tests for CampaignContext model."""

    def test_to_dict(self):
        ctx = CampaignContext(
            campaign_id="ctx_test",
            campaign_label="Context Test",
            ioc_members=["1.2.3.4", "evil.com"],
            temporal={"first_seen": "2026-01-01", "last_seen": "2026-01-02"},
            severity_distribution={"High": 2},
        )
        d = ctx.to_dict()
        assert d["campaign_id"] == "ctx_test"
        assert len(d["ioc_members"]) == 2
        assert d["severity_distribution"]["High"] == 2

    def test_empty_context(self):
        ctx = CampaignContext(
            campaign_id="empty",
            campaign_label="Empty",
            ioc_members=[],
        )
        assert ctx.graph_neighbors == {}
        assert ctx.mitre_context == []
        assert ctx.campaign_profile == ""


# ---------- Graph Traversal Tests ----------

from threat_intel_aggregator.predictive_graphrag.graph_traversal import GraphContextRetriever


class TestGraphContextRetriever:
    """Tests for graph-based context retrieval."""

    def _make_mock_kg(self):
        """Create a mock KG with a small graph."""
        import networkx as nx
        kg = MagicMock()
        G = nx.MultiDiGraph()
        G.add_node("1.2.3.4", type="ip", confidence=0.8)
        G.add_node("evil.com", type="domain", confidence=0.9)
        G.add_node("article_abc", type="context")
        G.add_edge("1.2.3.4", "article_abc", key=0, edge_type="MENTIONED_IN")
        G.add_edge("evil.com", "article_abc", key=0, edge_type="MENTIONED_IN")
        G.add_edge("1.2.3.4", "evil.com", key=0, edge_type="CO_OCCURS_WITH")
        kg.G = G
        return kg

    def test_get_graph_neighbors(self):
        kg = self._make_mock_kg()
        retriever = GraphContextRetriever(kg=kg, mitre_rag=None)
        neighbors = retriever._get_graph_neighbors(["1.2.3.4", "evil.com"])
        assert "1.2.3.4" in neighbors
        assert "evil.com" in neighbors["1.2.3.4"]

    def test_get_graph_neighbors_missing_node(self):
        kg = self._make_mock_kg()
        retriever = GraphContextRetriever(kg=kg, mitre_rag=None)
        neighbors = retriever._get_graph_neighbors(["nonexistent.com"])
        assert neighbors == {}

    def test_build_campaign_profile(self):
        retriever = GraphContextRetriever(kg=MagicMock(), mitre_rag=None)
        profile = retriever._build_campaign_profile(
            label="Test Campaign",
            ioc_members=["1.2.3.4", "evil.com"],
            temporal={"first_seen": "2026-01-01", "last_seen": "2026-01-02", "duration_hours": 24.0},
            severity_dist={"High": 2},
            type_dist={"ip": 1, "domain": 1},
            graph_neighbors={"1.2.3.4": ["evil.com"]},
        )
        assert "Test Campaign" in profile
        assert "Total IOCs: 2" in profile
        assert "24.0 hours" in profile
        assert "High: 2" in profile

    def test_retrieve_campaign_context(self):
        kg = self._make_mock_kg()
        retriever = GraphContextRetriever(kg=kg, mitre_rag=None)
        campaign = {
            "campaign_id": "test_001",
            "label": "Integration Test",
            "ioc_members": ["1.2.3.4", "evil.com"],
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-02T00:00:00Z",
            "duration_hours": 24.0,
            "severity_distribution": {"High": 2},
            "type_distribution": {"ip": 1, "domain": 1},
        }
        ctx = retriever.retrieve_campaign_context(campaign)
        assert ctx.campaign_id == "test_001"
        assert len(ctx.ioc_members) == 2
        assert "Integration Test" in ctx.campaign_profile

    def test_empty_campaign(self):
        retriever = GraphContextRetriever(kg=MagicMock(), mitre_rag=None)
        retriever._kg.G = MagicMock()
        retriever._kg.G.has_node.return_value = False
        campaign = {
            "campaign_id": "empty_001",
            "label": "Empty",
            "ioc_members": [],
        }
        ctx = retriever.retrieve_campaign_context(campaign)
        assert ctx.campaign_id == "empty_001"
        assert ctx.graph_neighbors == {}


# ---------- TTP Predictor Tests ----------

from threat_intel_aggregator.predictive_graphrag.ttp_predictor import TTPPredictor


class TestTTPPredictor:
    """Tests for agentic TTP prediction pipeline."""

    def test_extract_json_direct(self):
        predictor = TTPPredictor()
        raw = '{"current_stage": "Reconnaissance", "confidence": 0.8, "evidence": "test"}'
        result = predictor._extract_json(raw)
        assert result["current_stage"] == "Reconnaissance"

    def test_extract_json_markdown_wrapped(self):
        predictor = TTPPredictor()
        raw = '```json\n{"current_stage": "Execution"}\n```'
        result = predictor._extract_json(raw)
        assert result["current_stage"] == "Execution"

    def test_extract_json_with_text(self):
        predictor = TTPPredictor()
        raw = 'Here is the analysis:\n{"current_stage": "Persistence"}\nDone.'
        result = predictor._extract_json(raw)
        assert result["current_stage"] == "Persistence"

    def test_extract_json_invalid(self):
        predictor = TTPPredictor()
        result = predictor._extract_json("This is not JSON at all")
        assert result is None

    def test_fallback_prediction(self):
        predictor = TTPPredictor()
        preds = predictor._fallback_prediction("Initial Access")
        assert len(preds) == 3
        assert preds[0].tactic == "Execution"  # Next in kill chain
        assert preds[0].confidence > preds[1].confidence  # Decreasing confidence

    def test_fallback_prediction_last_stage(self):
        predictor = TTPPredictor()
        preds = predictor._fallback_prediction("Impact")
        assert len(preds) == 3
        # All should be "Impact" since it's the last stage
        assert all(p.tactic == "Impact" for p in preds)

    def test_format_mitre_context_empty(self):
        predictor = TTPPredictor()
        result = predictor._format_mitre_context([])
        assert result == ""

    def test_format_mitre_context(self):
        predictor = TTPPredictor()
        techniques = [
            {"technique_id": "T1059", "name": "Command Scripting", "tactics": ["Execution"], "description": "test"},
        ]
        result = predictor._format_mitre_context(techniques)
        assert "T1059" in result
        assert "Command Scripting" in result

    def test_format_graph_context_empty(self):
        predictor = TTPPredictor()
        result = predictor._format_graph_context({})
        assert result == ""

    @patch.object(TTPPredictor, '_query_ollama')
    def test_full_predict_mock(self, mock_ollama):
        """Integration test with mocked Ollama responses."""
        # Mock the 3 LLM calls
        mock_ollama.side_effect = [
            # Step 1: Stage classification
            '{"current_stage": "Command and Control", "confidence": 0.85, "evidence": "C2 indicators"}',
            # Step 2: Reasoning
            "Based on the C2 indicators, the attacker is likely to exfiltrate data next.",
            # Step 3: Prediction
            json.dumps({
                "predictions": [
                    {"tactic": "Exfiltration", "technique_id": "T1041", "technique_name": "Exfiltration Over C2", "confidence": 0.8, "reasoning": "C2 established"},
                    {"tactic": "Impact", "technique_id": "T1486", "technique_name": "Data Encrypted", "confidence": 0.6, "reasoning": "Ransomware pattern"},
                    {"tactic": "Collection", "technique_id": "T1005", "technique_name": "Data from Local System", "confidence": 0.5, "reasoning": "Pre-exfil collection"},
                ],
                "defensive_recommendations": ["Monitor outbound traffic", "Enable DLP"]
            }),
        ]

        predictor = TTPPredictor()
        context = CampaignContext(
            campaign_id="mock_test",
            campaign_label="Mock Campaign",
            ioc_members=["1.2.3.4", "evil.com"],
            campaign_profile="Campaign: Mock Campaign\nTotal IOCs: 2",
        )

        result = predictor.predict(context)

        assert result.campaign_id == "mock_test"
        assert result.current_stage == "Command and Control"
        assert len(result.predictions) == 3
        assert result.predictions[0].tactic == "Exfiltration"
        assert result.predictions[0].confidence == 0.8
        assert len(result.defensive_recommendations) == 2
        assert mock_ollama.call_count == 3

    @patch.object(TTPPredictor, '_query_ollama')
    def test_predict_with_ollama_failure(self, mock_ollama):
        """Test graceful degradation when Ollama fails."""
        mock_ollama.side_effect = RuntimeError("Ollama is not available")

        predictor = TTPPredictor()
        context = CampaignContext(
            campaign_id="fail_test",
            campaign_label="Fail Test",
            ioc_members=["1.2.3.4"],
            campaign_profile="Campaign: Fail Test\nDominant IOC type: ip\nTotal IOCs: 1",
        )

        result = predictor.predict(context)

        # Should fall back to heuristic classification (ip → Command and Control)
        assert result.current_stage != "Unknown"
        assert result.current_stage in [
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement", "Collection",
            "Command and Control", "Exfiltration", "Impact",
        ]
        assert len(result.predictions) == 3  # Fallback predictions
        assert len(result.defensive_recommendations) >= 1
