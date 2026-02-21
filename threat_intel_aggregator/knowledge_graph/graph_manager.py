import os
import json
import sqlite3
import networkx as nx
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable
from networkx.readwrite import json_graph

class ThreatKnowledgeGraph:
    SCHEMA_VERSION = "1.0"
    
    def __init__(self, data_dir: str = "data/knowledge_graph"):
        self.data_dir = data_dir
        self.json_path = os.path.join(data_dir, "graph.json")
        self.db_path = os.path.join(data_dir, "kg_metadata.db")
        os.makedirs(data_dir, exist_ok=True)
        
        self.graph = nx.MultiDiGraph()
        self._last_loaded_time = 0
        self.load()

    def _get_db_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self):
        with self._get_db_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS node_metadata (
                    node_id TEXT PRIMARY KEY,
                    provenance TEXT,
                    reviewed BOOLEAN DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS edge_provenance (
                    source TEXT,
                    target TEXT,
                    edge_key TEXT,
                    context_id TEXT,
                    timestamp TEXT,
                    PRIMARY KEY (source, target, edge_key, context_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.execute("INSERT OR IGNORE INTO graph_info (key, value) VALUES ('schema_version', ?)", (self.SCHEMA_VERSION,))

    def add_ioc_node(self, ioc_value: str, ioc_type: str, confidence: float, source: str):
        """Adds or updates an IOC node with Bayesian confidence fusion."""
        now = datetime.now(timezone.utc).isoformat()
        
        if self.graph.has_node(ioc_value):
            node_data = self.graph.nodes[ioc_value]
            old_conf = node_data.get("confidence", 0.5)
            # Bayesian Fusion: 1 - (1-p1)(1-p2)
            new_conf = 1 - (1 - old_conf) * (1 - confidence)
            
            node_data.update({
                "confidence": new_conf,
                "last_seen": now,
                "type": ioc_type
            })
        else:
            self.graph.add_node(
                ioc_value,
                type=ioc_type,
                confidence=confidence,
                first_seen=now,
                last_seen=now,
                reviewed=False
            )

        # Update SQL metadata for provenance
        with self._get_db_conn() as conn:
            row = conn.execute("SELECT provenance FROM node_metadata WHERE node_id = ?", (ioc_value,)).fetchone()
            if row:
                prov = json.loads(row[0])
                if source not in prov:
                    prov.append(source)
                conn.execute("UPDATE node_metadata SET provenance = ? WHERE node_id = ?", (json.dumps(prov), ioc_value))
            else:
                conn.execute("INSERT INTO node_metadata (node_id, provenance) VALUES (?, ?)", 
                             (ioc_value, json.dumps([source])))

    def add_relationship(self, source_id: str, target_id: str, edge_type: str, weight: float, context_id: str):
        """Adds a weighted edge scoped to a context_id (e.g. article URL hash)."""
        now = datetime.now(timezone.utc).isoformat()
        
        # In MultiDiGraph, multiple edges can exist between same nodes. 
        # We use (edge_type, context_id) as part of the key if needed, or just let MultiDiGraph handle it.
        # But to avoid duplicate edges for same context, we'll check SQL.
        
        edge_id = f"{edge_type}:{context_id}"
        
        if not self.graph.has_edge(source_id, target_id, key=edge_id):
            self.graph.add_edge(
                source_id,
                target_id,
                key=edge_id,
                type=edge_type,
                weight=weight,
                context_id=context_id,
                timestamp=now
            )
            
            with self._get_db_conn() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO edge_provenance (source, target, edge_key, context_id, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (source_id, target_id, edge_id, context_id, now))

    def apply_decay(self, now: datetime, halflife_days: float = 30):
        """Decays non-reviewed nodes based on wall-clock time."""
        for node, data in self.graph.nodes(data=True):
            if data.get("reviewed", False):
                continue
            
            last_seen_str = data.get("last_seen")
            if not last_seen_str:
                continue
                
            last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
            elapsed_hours = (now - last_seen).total_seconds() / 3600
            
            decay_factor = 0.5 ** (elapsed_hours / (halflife_days * 24))
            data["confidence"] *= decay_factor

        # Also decay edges? (Optional, but good for cleanliness)
        for u, v, k, data in self.graph.edges(data=True, keys=True):
            ts_str = data.get("timestamp")
            if not ts_str:
                continue
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            elapsed_hours = (now - ts).total_seconds() / 3600
            decay_factor = 0.5 ** (elapsed_hours / (halflife_days * 24))
            data["weight"] *= decay_factor

    def get_top_nodes(self, n: int = 100):
        """Returns top N nodes sorted by centrality (Degree for now, PageRank later if size allows)."""
        if not self.graph.nodes:
            return []
            
        # Degree centrality weighted by confidence
        centrality = {node: self.graph.degree(node) * data.get("confidence", 0) 
                      for node, data in self.graph.nodes(data=True)}
        
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:n]
        return [{"id": node, "score": score, **self.graph.nodes[node]} for node, score in sorted_nodes]

    def persist(self):
        """Saves graph structure to JSON and metadata to SQLite."""
        self._init_db()
        data = json_graph.node_link_data(self.graph)
        data["schema_version"] = self.SCHEMA_VERSION
        
        with open(self.json_path, 'w') as f:
            json.dump(data, f, indent=2)
            
        print(f"💾 Graph persisted to {self.json_path} ({len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges)")

    def load(self):
        """Hydrates memory from JSON + SQLite."""
        if not os.path.exists(self.json_path):
            self._init_db()
            return

        # Optimization: skip if file hasn't changed
        mtime = os.path.getmtime(self.json_path)
        if mtime <= self._last_loaded_time:
            return

        with open(self.json_path, 'r') as f:
            data = json.load(f)
            
        if data.get("schema_version") != self.SCHEMA_VERSION:
            print(f"⚠️ Schema version mismatch: expected {self.SCHEMA_VERSION}, found {data.get('schema_version')}")
            # Handle migration if needed

        self.graph = json_graph.node_link_graph(data, multigraph=True, directed=True)
        self._last_loaded_time = mtime
        
        # Merge SQL metadata (reviewed status)
        self._init_db()
        with self._get_db_conn() as conn:
            cursor = conn.execute("SELECT node_id, reviewed FROM node_metadata")
            for node_id, reviewed in cursor:
                if self.graph.has_node(node_id):
                    self.graph.nodes[node_id]["reviewed"] = bool(reviewed)
        
        print(f"✅ Graph loaded: {len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges")

    def update_from_batch(self, normalized_iocs: List[Dict], context_id: str):
        """Orchestrates updating nodes and edges from a single article batch."""
        ioc_values = []
        for ioc in normalized_iocs:
            val = ioc.get("ioc")
            if not val: continue
            
            self.add_ioc_node(
                ioc_value=val,
                ioc_type=ioc.get("type", "unknown"),
                confidence=ioc.get("fused_confidence", 0.5),
                source=ioc.get("feed", "unknown")
            )
            ioc_values.append(val)
            
        # Add co-occurrence edges (clique within the article)
        for i, val1 in enumerate(ioc_values):
            for val2 in ioc_values[i+1:]:
                # Weighted by the average confidence of the two IOCs
                w1 = self.graph.nodes[val1].get("confidence", 0.5)
                w2 = self.graph.nodes[val2].get("confidence", 0.5)
                weight = (w1 + w2) / 2
                
                self.add_relationship(val1, val2, "CO_OCCURS_WITH", weight, context_id)
