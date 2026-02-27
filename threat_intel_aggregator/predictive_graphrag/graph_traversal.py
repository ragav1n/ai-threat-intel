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

    def __init__(self, kg=None, mitre_rag=None):
        """
        Args:
            kg: ThreatKnowledgeGraph instance (lazy-loaded if None).
            mitre_rag: MitreRAG instance (lazy-loaded if None).
        """
        self._kg = kg
        self._mitre_rag = mitre_rag

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

        # 3. Graph neighborhood traversal
        graph_neighbors = self._get_graph_neighbors(ioc_members)

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
        Traverse 1-hop neighbors in the KG for each campaign IOC.

        Returns:
            Dict mapping each IOC → list of neighboring node IDs.
        """
        neighbors: Dict[str, List[str]] = {}
        try:
            graph = self.kg.G
            for ioc in ioc_members[:50]:  # Cap to prevent overload
                if graph.has_node(ioc):
                    # Get all neighbors (both predecessors and successors for DiGraph)
                    node_neighbors = set()
                    if hasattr(graph, 'predecessors'):
                        node_neighbors.update(graph.predecessors(ioc))
                    if hasattr(graph, 'successors'):
                        node_neighbors.update(graph.successors(ioc))
                    # Remove self
                    node_neighbors.discard(ioc)
                    neighbors[ioc] = list(node_neighbors)[:20]  # Cap neighbors per node
        except Exception as e:
            logger.warning(f"Graph neighbor retrieval failed: {e}")

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
        graph_neighbors: Dict[str, List[str]],
    ) -> str:
        """
        Build a natural language campaign profile for the LLM.

        This is the primary context that feeds into the agentic prediction pipeline.
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

        # Graph connectivity
        total_neighbors = sum(len(n) for n in graph_neighbors.values())
        connected_iocs = len(graph_neighbors)
        lines.append(f"Graph connectivity: {connected_iocs} IOCs have {total_neighbors} total neighbors in the knowledge graph")

        # Co-occurring IOCs from graph
        all_neighbors = []
        for neigh_list in graph_neighbors.values():
            all_neighbors.extend(neigh_list)
        if all_neighbors:
            neighbor_counts = Counter(all_neighbors)
            top_neighbors = neighbor_counts.most_common(5)
            top_str = ", ".join(f"{n} (seen {c}x)" for n, c in top_neighbors)
            lines.append(f"Most connected external nodes: {top_str}")

        return "\n".join(lines)

    def close(self):
        """Release resources."""
        if self._kg is not None:
            try:
                self._kg.close()
            except Exception:
                pass
