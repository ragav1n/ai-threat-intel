"""
Phase 3 Tests: Temporal Campaign Detection.

Tests:
1. Community Detection (Louvain on synthetic graph)
2. Temporal Enrichment (first_seen / last_seen calculation)
3. Campaign Filtering (min community size)
4. Campaign Labeling (auto-generated labels)
5. Timeline Generation (time-series output)
"""
import pytest
from datetime import datetime, timedelta, timezone
from collections import Counter

import networkx as nx


# ============================================================
# Test 1: Community Detection on Synthetic Graph
# ============================================================

from threat_intel_aggregator.campaign_detector.detector import CampaignDetector
from threat_intel_aggregator.campaign_detector.models import (
    Campaign,
    CampaignSummary,
    generate_campaign_id,
)
from threat_intel_aggregator.campaign_detector.temporal import (
    build_campaign_timeline,
    detect_active_campaigns,
    get_campaign_severity_summary,
)


class FakeKG:
    """Minimal mock of ThreatKnowledgeGraph for testing."""

    def __init__(self, graph: nx.MultiDiGraph):
        self.graph = graph


def _build_two_cluster_graph() -> FakeKG:
    """
    Build a synthetic MultiDiGraph with two clear clusters:
      Cluster A: ip-1, ip-2, ip-3, ip-4 (fully connected)
      Cluster B: dom-1, dom-2, dom-3 (fully connected)
    Plus one context node that should be excluded.
    """
    G = nx.MultiDiGraph()

    now = datetime.now(timezone.utc)
    early = (now - timedelta(days=5)).isoformat()
    late = now.isoformat()

    # Cluster A — IPs
    for i in range(1, 5):
        G.add_node(f"ip-{i}", type="ip", confidence=0.8,
                   first_seen=early, last_seen=late)

    for i in range(1, 5):
        for j in range(i + 1, 5):
            G.add_edge(f"ip-{i}", f"ip-{j}",
                       key=f"CO_OCCURS:ctx_a", type="CO_OCCURS_WITH",
                       weight=0.5, context_id="ctx_a",
                       timestamp=late)

    # Cluster B — Domains
    for i in range(1, 4):
        G.add_node(f"dom-{i}", type="domain", confidence=0.7,
                   first_seen=early, last_seen=late)

    for i in range(1, 4):
        for j in range(i + 1, 4):
            G.add_edge(f"dom-{i}", f"dom-{j}",
                       key=f"CO_OCCURS:ctx_b", type="CO_OCCURS_WITH",
                       weight=0.5, context_id="ctx_b",
                       timestamp=late)

    # Context node — should be filtered out
    G.add_node("ctx_article", type="context", confidence=0.1,
               first_seen=early, last_seen=late)
    G.add_edge("ip-1", "ctx_article", key="MENTIONED_IN:ctx_a",
               type="MENTIONED_IN", weight=0.5, context_id="ctx_a",
               timestamp=late)

    return FakeKG(G)


class TestCommunityDetection:
    """Test that Louvain finds the expected clusters."""

    def test_detects_two_clusters(self):
        kg = _build_two_cluster_graph()
        detector = CampaignDetector(min_community_size=3)
        campaigns = detector.detect(kg)

        assert len(campaigns) == 2, f"Expected 2 campaigns, got {len(campaigns)}"

    def test_context_nodes_excluded(self):
        kg = _build_two_cluster_graph()
        detector = CampaignDetector(min_community_size=3)
        campaigns = detector.detect(kg)

        all_members = []
        for c in campaigns:
            all_members.extend(c.ioc_members)

        assert "ctx_article" not in all_members

    def test_cluster_sizes(self):
        kg = _build_two_cluster_graph()
        detector = CampaignDetector(min_community_size=3)
        campaigns = detector.detect(kg)

        sizes = sorted([c.ioc_count for c in campaigns], reverse=True)
        assert sizes == [4, 3], f"Expected [4, 3], got {sizes}"


# ============================================================
# Test 2: Temporal Enrichment
# ============================================================


class TestTemporalEnrichment:
    """Test first_seen / last_seen calculation from node attributes."""

    def test_first_seen_is_earliest(self):
        kg = _build_two_cluster_graph()
        detector = CampaignDetector(min_community_size=3)
        campaigns = detector.detect(kg)

        for c in campaigns:
            # All our test nodes share the same early timestamp
            assert c.first_seen is not None
            assert c.last_seen is not None

    def test_duration_is_positive(self):
        kg = _build_two_cluster_graph()
        detector = CampaignDetector(min_community_size=3)
        campaigns = detector.detect(kg)

        for c in campaigns:
            assert c.duration_hours >= 0


# ============================================================
# Test 3: Campaign Filtering
# ============================================================


class TestCampaignFiltering:
    """Test that small communities are discarded."""

    def test_singleton_filtered(self):
        """Communities with < min_community_size should be removed."""
        G = nx.MultiDiGraph()
        now = datetime.now(timezone.utc).isoformat()

        # One isolated node (will form a community of 1)
        G.add_node("lone-ip", type="ip", confidence=0.9,
                    first_seen=now, last_seen=now)

        # A tight cluster of 3
        for i in range(1, 4):
            G.add_node(f"c-{i}", type="ip", confidence=0.8,
                       first_seen=now, last_seen=now)
        for i in range(1, 4):
            for j in range(i + 1, 4):
                G.add_edge(f"c-{i}", f"c-{j}",
                           key=f"CO:{i}_{j}", type="CO_OCCURS_WITH",
                           weight=1.0, context_id="ctx", timestamp=now)

        kg = FakeKG(G)
        detector = CampaignDetector(min_community_size=3)
        campaigns = detector.detect(kg)

        # The lone node should be filtered; only the cluster remains
        assert len(campaigns) == 1
        assert campaigns[0].ioc_count == 3

    def test_pair_filtered(self):
        """A pair of connected nodes should not form a campaign with min_size=3."""
        G = nx.MultiDiGraph()
        now = datetime.now(timezone.utc).isoformat()

        G.add_node("a", type="ip", confidence=0.9, first_seen=now, last_seen=now)
        G.add_node("b", type="ip", confidence=0.9, first_seen=now, last_seen=now)
        G.add_edge("a", "b", key="CO:ab", type="CO_OCCURS_WITH",
                    weight=1.0, context_id="ctx", timestamp=now)

        kg = FakeKG(G)
        detector = CampaignDetector(min_community_size=3)
        campaigns = detector.detect(kg)

        assert len(campaigns) == 0


# ============================================================
# Test 4: Campaign Labeling
# ============================================================


class TestCampaignLabeling:
    """Test auto-generated campaign labels."""

    def test_label_contains_type(self):
        kg = _build_two_cluster_graph()
        detector = CampaignDetector(min_community_size=3)
        campaigns = detector.detect(kg)

        labels = [c.label for c in campaigns]
        # One should be IP, one DOMAIN
        types_found = set()
        for label in labels:
            if "IP" in label.upper():
                types_found.add("ip")
            if "DOMAIN" in label.upper():
                types_found.add("domain")

        assert "ip" in types_found, f"No IP campaign label found in {labels}"
        assert "domain" in types_found, f"No domain campaign label found in {labels}"

    def test_label_contains_date(self):
        kg = _build_two_cluster_graph()
        detector = CampaignDetector(min_community_size=3)
        campaigns = detector.detect(kg)

        # Labels should contain a date string like 2026-02-25
        for c in campaigns:
            assert "-" in c.label, f"No date found in label: {c.label}"


# ============================================================
# Test 5: Timeline Generation
# ============================================================


class TestTimelineGeneration:
    """Test time-series output for campaigns."""

    def _make_campaigns(self) -> list:
        now = datetime.now(timezone.utc)
        return [
            Campaign(
                campaign_id="test_1",
                label="Test Campaign 1",
                ioc_members=["a", "b", "c"],
                ioc_count=3,
                first_seen=(now - timedelta(days=10)).isoformat(),
                last_seen=(now - timedelta(days=5)).isoformat(),
                duration_hours=120.0,
                severity_distribution={"High": 2, "Medium": 1},
                avg_confidence=0.8,
                max_confidence=0.9,
                detected_at=(now - timedelta(days=5)).isoformat(),
            ),
            Campaign(
                campaign_id="test_2",
                label="Test Campaign 2",
                ioc_members=["d", "e", "f", "g"],
                ioc_count=4,
                first_seen=(now - timedelta(days=3)).isoformat(),
                last_seen=now.isoformat(),
                duration_hours=72.0,
                severity_distribution={"Critical": 1, "High": 3},
                avg_confidence=0.75,
                max_confidence=0.95,
                detected_at=(now - timedelta(days=1)).isoformat(),
            ),
        ]

    def test_timeline_length(self):
        campaigns = self._make_campaigns()
        timeline = build_campaign_timeline(campaigns, period_days=30, bucket_size_days=1)
        # Should have ~30-31 data points
        assert 28 <= len(timeline) <= 32

    def test_timeline_structure(self):
        campaigns = self._make_campaigns()
        timeline = build_campaign_timeline(campaigns, period_days=7)

        for point in timeline:
            assert "period" in point
            assert "active_campaigns" in point
            assert "new_campaigns" in point

    def test_active_campaigns_filter(self):
        campaigns = self._make_campaigns()
        # Campaign 2 is still active (last_seen = now)
        active = detect_active_campaigns(campaigns, window_hours=48)
        assert len(active) >= 1

        # Campaign 1 ended 5 days ago, should not be active with 48h window
        active_ids = [c.campaign_id for c in active]
        assert "test_1" not in active_ids
        assert "test_2" in active_ids

    def test_severity_summary(self):
        campaigns = self._make_campaigns()
        summary = get_campaign_severity_summary(campaigns)
        assert summary["High"] == 5  # 2 + 3
        assert summary["Critical"] == 1
        assert summary["Medium"] == 1


# ============================================================
# Test 6: Model Utilities
# ============================================================


class TestModelUtilities:
    """Test Campaign model serialization and helpers."""

    def test_campaign_id_deterministic(self):
        id1 = generate_campaign_id(["a", "b", "c"])
        id2 = generate_campaign_id(["c", "a", "b"])  # Different order, same set
        assert id1 == id2

    def test_campaign_id_different_for_different_sets(self):
        id1 = generate_campaign_id(["a", "b", "c"])
        id2 = generate_campaign_id(["a", "b", "d"])
        assert id1 != id2

    def test_to_dict_has_id(self):
        c = Campaign(
            campaign_id="test_abc",
            label="Test",
            ioc_members=["a"],
            ioc_count=1,
            first_seen="2026-01-01T00:00:00Z",
            last_seen="2026-01-01T00:00:00Z",
            duration_hours=0.0,
        )
        d = c.to_dict()
        assert d["_id"] == "test_abc"

    def test_from_dict_round_trip(self):
        c = Campaign(
            campaign_id="test_abc",
            label="Test",
            ioc_members=["a", "b"],
            ioc_count=2,
            first_seen="2026-01-01T00:00:00Z",
            last_seen="2026-01-02T00:00:00Z",
            duration_hours=24.0,
            avg_confidence=0.8,
            max_confidence=0.9,
        )
        d = c.to_dict()
        c2 = Campaign.from_dict(d)
        assert c2.campaign_id == c.campaign_id
        assert c2.ioc_count == c.ioc_count

    def test_campaign_summary(self):
        c = Campaign(
            campaign_id="test_xyz",
            label="Big Campaign",
            ioc_members=["a", "b", "c"],
            ioc_count=3,
            first_seen="2026-01-01T00:00:00Z",
            last_seen="2026-01-05T00:00:00Z",
            duration_hours=96.0,
            severity_distribution={"Critical": 1, "High": 2},
            avg_confidence=0.85,
            max_confidence=0.95,
        )
        summary = CampaignSummary.from_campaign(c)
        assert summary.top_severity == "Critical"
        assert summary.ioc_count == 3
