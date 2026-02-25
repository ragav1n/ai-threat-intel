"""
Campaign Detector — Louvain community detection on the Knowledge Graph.

Projects the KG's MultiDiGraph into an undirected IOC-only graph,
runs Louvain community detection, and enriches each community with
temporal and severity metadata.
"""
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import networkx as nx

try:
    import community.community_louvain as community_louvain
except ImportError:
    community_louvain = None

from .models import Campaign, generate_campaign_id

logger = logging.getLogger(__name__)


class CampaignDetector:
    """Detects coordinated threat campaigns from the Knowledge Graph."""

    def __init__(
        self,
        min_community_size: int = 3,
        resolution: float = 1.0,
    ):
        """
        Args:
            min_community_size: Minimum IOC count to keep a community.
            resolution: Louvain resolution parameter (higher = more communities).
        """
        self.min_community_size = min_community_size
        self.resolution = resolution

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, kg) -> List[Campaign]:
        """
        Run full campaign detection pipeline on a ThreatKnowledgeGraph.

        Steps:
            1. Project IOC-only undirected graph
            2. Run Louvain community detection
            3. Enrich each community with temporal + severity metadata
            4. Filter trivial communities

        Args:
            kg: A ThreatKnowledgeGraph instance.

        Returns:
            List of Campaign objects, sorted by ioc_count descending.
        """
        if community_louvain is None:
            logger.error("python-louvain is not installed. Run: pip install python-louvain")
            return []

        projected = self._project_ioc_graph(kg.graph)
        if len(projected.nodes) < self.min_community_size:
            logger.info("Graph too small for campaign detection (%d IOC nodes)", len(projected.nodes))
            return []

        partition = self._run_louvain(projected)
        communities = self._group_communities(partition)
        campaigns = self._enrich_communities(communities, kg.graph)

        # Sort by IOC count descending
        campaigns.sort(key=lambda c: c.ioc_count, reverse=True)
        logger.info("🔍 Detected %d campaigns (%d communities filtered out)",
                     len(campaigns),
                     len(communities) - len(campaigns))
        return campaigns

    # ------------------------------------------------------------------
    # Pipeline Steps
    # ------------------------------------------------------------------

    def _project_ioc_graph(self, multigraph: nx.MultiDiGraph) -> nx.Graph:
        """
        Create an undirected simple graph of IOC-only nodes.
        Edge weights are summed across all parallel directed edges.
        """
        G = nx.Graph()

        for node, data in multigraph.nodes(data=True):
            if data.get("type", "").lower() == "context":
                continue
            G.add_node(node, **data)

        for u, v, _k, data in multigraph.edges(data=True, keys=True):
            if u not in G.nodes or v not in G.nodes:
                continue
            w = data.get("weight", 0.5)
            if G.has_edge(u, v):
                G[u][v]["weight"] += w
            else:
                G.add_edge(u, v, weight=w)

        return G

    def _run_louvain(self, G: nx.Graph) -> Dict[str, int]:
        """Run Louvain community detection. Returns node → community_id mapping."""
        partition = community_louvain.best_partition(
            G,
            weight="weight",
            resolution=self.resolution,
            random_state=42,
        )
        num_communities = len(set(partition.values()))
        logger.info("Louvain found %d communities from %d nodes", num_communities, len(G.nodes))
        return partition

    def _group_communities(self, partition: Dict[str, int]) -> Dict[int, List[str]]:
        """Group partition mapping into {community_id: [list of IOC values]}."""
        communities: Dict[int, List[str]] = {}
        for node, comm_id in partition.items():
            communities.setdefault(comm_id, []).append(node)
        return communities

    def _enrich_communities(
        self,
        communities: Dict[int, List[str]],
        graph: nx.MultiDiGraph,
    ) -> List[Campaign]:
        """Enrich each community with temporal, severity, and provenance metadata."""
        now = datetime.now(timezone.utc).isoformat()
        campaigns: List[Campaign] = []

        for _comm_id, members in communities.items():
            if len(members) < self.min_community_size:
                continue

            # Temporal analysis
            first_seen_dt = None
            last_seen_dt = None
            confidences = []
            severity_counter: Counter = Counter()
            type_counter: Counter = Counter()
            feeds: set = set()

            for ioc in members:
                data = graph.nodes.get(ioc, {})

                # Temporal
                fs = data.get("first_seen")
                ls = data.get("last_seen")
                if fs:
                    try:
                        dt = datetime.fromisoformat(fs.replace("Z", "+00:00"))
                        if first_seen_dt is None or dt < first_seen_dt:
                            first_seen_dt = dt
                    except (ValueError, TypeError):
                        pass
                if ls:
                    try:
                        dt = datetime.fromisoformat(ls.replace("Z", "+00:00"))
                        if last_seen_dt is None or dt > last_seen_dt:
                            last_seen_dt = dt
                    except (ValueError, TypeError):
                        pass

                # Confidence
                conf = data.get("confidence", 0.0)
                confidences.append(conf)

                # Type
                ioc_type = data.get("type", "unknown")
                type_counter[ioc_type] += 1

            # Severity from IOC type heuristic
            severity_map = {
                "ip": "Medium", "ipv6": "Medium", "domain": "Medium",
                "url": "High", "md5": "High", "sha1": "High", "sha256": "High",
                "email": "Low", "cve": "Critical",
            }
            for ioc_type, count in type_counter.items():
                sev = severity_map.get(ioc_type.lower(), "Unknown")
                severity_counter[sev] += count

            # Duration
            if first_seen_dt and last_seen_dt:
                duration_hours = (last_seen_dt - first_seen_dt).total_seconds() / 3600
            else:
                duration_hours = 0.0

            first_seen = first_seen_dt.isoformat() if first_seen_dt else now
            last_seen = last_seen_dt.isoformat() if last_seen_dt else now

            # Label generation
            dominant_type = type_counter.most_common(1)[0][0] if type_counter else "Mixed"
            date_label = (first_seen_dt or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
            label = f"{dominant_type.upper()} Campaign {date_label}"

            # Retrieve feed sources from node provenance (via graph neighbors)
            # We look at context nodes linked to these IOCs
            for ioc in members:
                for neighbor in graph.neighbors(ioc):
                    neighbor_data = graph.nodes.get(neighbor, {})
                    if neighbor_data.get("type") == "context":
                        # Context node label often holds the feed name
                        continue
                # Feed sources aren't directly on IOC nodes in the current model:
                # we'll collect from provenance metadata if available (sqlite).
                # For now, leave feed_sources empty — the API will enrich from SQLite.

            campaign = Campaign(
                campaign_id=generate_campaign_id(members),
                label=label,
                ioc_members=sorted(members),
                ioc_count=len(members),
                first_seen=first_seen,
                last_seen=last_seen,
                duration_hours=round(duration_hours, 2),
                severity_distribution=dict(severity_counter),
                type_distribution=dict(type_counter),
                feed_sources=sorted(feeds),
                avg_confidence=round(sum(confidences) / len(confidences), 4) if confidences else 0.0,
                max_confidence=round(max(confidences), 4) if confidences else 0.0,
                detected_at=now,
            )
            campaigns.append(campaign)

        return campaigns
