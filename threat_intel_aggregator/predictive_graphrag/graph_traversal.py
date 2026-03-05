"""
Graph-based Context Retrieval for Predictive TTP Forecasting.

Traverses the Knowledge Graph and campaign data to build rich context
that feeds into the agentic LLM prediction pipeline.
"""
import logging
from typing import Dict, List, Any, Optional
from collections import Counter

from .models import CampaignContext

logger = logging.getLogger(__name__)


class GraphContextRetriever:
    """
    Retrieves rich predictive context from the Knowledge Graph
    and campaign data for a target campaign.
    """

    def __init__(self, kg=None, mitre_rag=None, max_hops: int = 2):
        """
        Args:
            kg: ThreatKnowledgeGraph instance (lazy-loaded if None).
            mitre_rag: MitreRAG instance (lazy-loaded if None).
            max_hops: Depth of multi-hop graph traversal (default: 2).
        """
        self._kg = kg
        self._mitre_rag = mitre_rag
        self.max_hops = max_hops

    @property
    def kg(self):
        if self._kg is None:
            from threat_intel_aggregator.knowledge_graph.graph_manager import ThreatKnowledgeGraph
            self._kg = ThreatKnowledgeGraph(data_dir="data/knowledge_graph", read_only=True)
        return self._kg

    @property
    def mitre_rag(self):
        if self._mitre_rag is None:
            try:
                from threat_model.threat_summarizer.mitre_rag import get_mitre_rag
                self._mitre_rag = get_mitre_rag()
            except Exception as e:
                logger.warning(f"MITRE RAG unavailable: {e}")
                self._mitre_rag = None
        return self._mitre_rag

    def retrieve_campaign_context(self, campaign: dict) -> CampaignContext:
        """
        Orchestrate full context retrieval for a campaign.

        Args:
            campaign: Campaign document from MongoDB (dict with campaign_id,
                      ioc_members, severity_distribution, etc.)

        Returns:
            CampaignContext with all retrieved context.
        """
        campaign_id = campaign.get("campaign_id", "unknown")
        label = campaign.get("label", "Unknown Campaign")
        ioc_members = campaign.get("ioc_members", [])

        logger.info(f"Retrieving context for campaign {campaign_id} ({len(ioc_members)} IOCs)")

        # 1. Temporal context
        temporal = {
            "first_seen": campaign.get("first_seen", ""),
            "last_seen": campaign.get("last_seen", ""),
            "duration_hours": campaign.get("duration_hours", 0),
        }

        # 2. Severity & type distributions
        severity_dist = campaign.get("severity_distribution", {})
        type_dist = campaign.get("type_distribution", {})

        # 3. Graph neighborhood traversal (multi-hop)
        graph_neighbors = self._get_multi_hop_neighbors(ioc_members, self.max_hops)

        # 4. MITRE ATT&CK context retrieval
        mitre_context = self._retrieve_mitre_context(ioc_members, type_dist, severity_dist)

        # 5. Build natural language campaign profile
        profile = self._build_campaign_profile(
            label, ioc_members, temporal, severity_dist, type_dist, graph_neighbors
        )

        return CampaignContext(
            campaign_id=campaign_id,
            campaign_label=label,
            ioc_members=ioc_members,
            temporal=temporal,
            severity_distribution=severity_dist,
            type_distribution=type_dist,
            graph_neighbors=graph_neighbors,
            mitre_context=mitre_context,
            campaign_profile=profile,
        )

    def _get_graph_neighbors(self, ioc_members: List[str]) -> Dict[str, List[str]]:
        """
        [Legacy] Traverse 1-hop neighbors in the KG for each campaign IOC.

        Returns:
            Dict mapping each IOC → list of neighboring node IDs.
        """
        hop_data = self._get_multi_hop_neighbors(ioc_members, max_hops=1)
        # Flatten to backward-compatible format
        return {ioc: list(hops.get(1, [])) for ioc, hops in hop_data.items()}

    def _get_multi_hop_neighbors(
        self,
        ioc_members: List[str],
        max_hops: int = 2,
        max_per_hop: int = 15,
    ) -> Dict[str, Dict[int, List[str]]]:
        """
        Multi-hop BFS traversal of the Knowledge Graph.

        Args:
            ioc_members: IOC node IDs to start traversal from.
            max_hops: Maximum depth (1 = immediate neighbors, 2 = neighbors of neighbors).
            max_per_hop: Maximum nodes to collect per hop to avoid explosion.

        Returns:
            Dict mapping each IOC → {hop_level: [neighbor_node_ids]}
        """
        neighbors: Dict[str, Dict[int, List[str]]] = {}
        try:
            graph = self.kg.G
            for ioc in ioc_members[:50]:  # Cap IOCs to prevent overload
                if not graph.has_node(ioc):
                    continue

                hop_neighbors: Dict[int, List[str]] = {}
                visited = {ioc}
                current_frontier = {ioc}

                for hop in range(1, max_hops + 1):
                    next_frontier: set = set()
                    for node in current_frontier:
                        if hasattr(graph, 'predecessors'):
                            next_frontier.update(graph.predecessors(node))
                        if hasattr(graph, 'successors'):
                            next_frontier.update(graph.successors(node))

                    # Remove already-visited nodes to avoid cycles
                    next_frontier -= visited
                    visited.update(next_frontier)

                    hop_neighbors[hop] = list(next_frontier)[:max_per_hop]
                    current_frontier = next_frontier

                    if not next_frontier:
                        break  # Graph exhausted at this depth

                neighbors[ioc] = hop_neighbors

        except Exception as e:
            logger.warning(f"Multi-hop graph traversal failed: {e}")

        return neighbors

    def _retrieve_mitre_context(
        self,
        ioc_members: List[str],
        type_dist: Dict[str, int],
        severity_dist: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        """
        Query MITRE ATT&CK RAG for techniques relevant to this campaign.

        Builds a semantic query from the campaign's IOC types and severity profile.
        """
        if self.mitre_rag is None:
            return []

        try:
            # Build semantic query from campaign characteristics
            query_parts = []

            # IOC type signals
            type_signals = {
                "ip": "network connection command-and-control",
                "domain": "DNS resolution domain generation phishing",
                "url": "web exploitation payload delivery",
                "md5": "malware file hash persistence",
                "sha1": "malware file hash persistence",
                "sha256": "malware file hash persistence",
                "cve": "vulnerability exploitation initial access",
                "email": "phishing social engineering",
            }
            for ioc_type, count in sorted(type_dist.items(), key=lambda x: -x[1]):
                if ioc_type.lower() in type_signals:
                    query_parts.append(type_signals[ioc_type.lower()])

            # Severity signals
            if severity_dist.get("Critical", 0) > 0 or severity_dist.get("High", 0) > 0:
                query_parts.append("advanced persistent threat lateral movement exfiltration")

            query = " ".join(query_parts) if query_parts else "threat campaign indicators of compromise"

            # Retrieve top-5 relevant MITRE techniques
            techniques = self.mitre_rag.retrieve_context(query, top_k=5)
            return techniques

        except Exception as e:
            logger.warning(f"MITRE RAG retrieval failed: {e}")
            return []

    def _build_campaign_profile(
        self,
        label: str,
        ioc_members: List[str],
        temporal: dict,
        severity_dist: Dict[str, int],
        type_dist: Dict[str, int],
        graph_neighbors: Dict[str, Dict[int, List[str]]],
    ) -> str:
        """
        Build a natural language campaign profile for the LLM.

        This is the primary context that feeds into the agentic prediction pipeline.
        Includes multi-hop graph connectivity to give the LLM a global threat web view.
        """
        lines = [f"Campaign: {label}"]
        lines.append(f"Total IOCs: {len(ioc_members)}")

        # Temporal
        if temporal.get("first_seen"):
            lines.append(f"First seen: {temporal['first_seen']}")
        if temporal.get("last_seen"):
            lines.append(f"Last seen: {temporal['last_seen']}")
        if temporal.get("duration_hours"):
            lines.append(f"Duration: {temporal['duration_hours']:.1f} hours")

        # IOC type breakdown
        if type_dist:
            type_str = ", ".join(f"{k}: {v}" for k, v in sorted(type_dist.items(), key=lambda x: -x[1]))
            lines.append(f"IOC types: {type_str}")

        # Severity breakdown
        if severity_dist:
            sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(severity_dist.items(), key=lambda x: -x[1]))
            lines.append(f"Severity distribution: {sev_str}")

        # IOC samples (first 10)
        if ioc_members:
            samples = ioc_members[:10]
            lines.append(f"Sample IOCs: {', '.join(samples)}")

        # Multi-hop graph context
        total_connected = len(graph_neighbors)
        if total_connected > 0:
            # Calculate totals per hop level
            hop_totals: Dict[int, int] = {}
            all_hop1: List[str] = []
            all_hop2: List[str] = []
            for hops in graph_neighbors.values():
                for hop_level, nodes in hops.items():
                    hop_totals[hop_level] = hop_totals.get(hop_level, 0) + len(nodes)
                    if hop_level == 1:
                        all_hop1.extend(nodes)
                    elif hop_level == 2:
                        all_hop2.extend(nodes)

            total_neighbors = sum(hop_totals.values())
            lines.append(
                f"Graph connectivity: {total_connected} IOCs connected to "
                f"{total_neighbors} nodes across {len(hop_totals)} hops"
            )

            # Hop-1: immediate neighbors (blast radius)
            if all_hop1:
                top_hop1 = Counter(all_hop1).most_common(5)
                hop1_str = ", ".join(f"{n} ({c}x)" for n, c in top_hop1)
                lines.append(f"Hop-1 neighbors (immediate blast radius): {hop1_str}")

            # Hop-2: second-degree neighbors (extended web)
            if all_hop2:
                top_hop2 = Counter(all_hop2).most_common(5)
                hop2_str = ", ".join(f"{n} ({c}x)" for n, c in top_hop2)
                lines.append(f"Hop-2 neighbors (extended threat web): {hop2_str}")
        else:
            lines.append("Graph connectivity: No known graph connections for this campaign")

        return "\n".join(lines)

    def close(self):
        """Release resources."""
        if self._kg is not None:
            try:
                self._kg.close()
            except Exception:
                pass
