import os
import json
import sqlite3
import networkx as nx
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable
from networkx.readwrite import json_graph

class ThreatKnowledgeGraph:
    SCHEMA_VERSION = "1.0"
    
    def __init__(self, data_dir: str = "data/knowledge_graph", read_only: bool = False):
        self.data_dir = data_dir
        self.read_only = read_only
        self.json_path = os.path.join(data_dir, "graph.json")
        self.db_path = os.path.join(data_dir, "kg_metadata.db")
        os.makedirs(data_dir, exist_ok=True)
        
        self.graph = nx.MultiDiGraph()
        self._last_loaded_time = 0
        self._db_conn = None
        
        if not self.read_only:
            self._init_db()
        self.load()

    def _get_db_conn(self):
        if self._db_conn is None:
            # Increase timeout to 30s to handle concurrent access
            self._db_conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
            self._db_conn.isolation_level = None  # Manual transaction control
            self._db_conn.execute("PRAGMA foreign_keys = ON")
            self._db_conn.execute("PRAGMA journal_mode = WAL")
            self._db_conn.execute("PRAGMA synchronous = NORMAL")
            if self.read_only:
                 self._db_conn.execute("PRAGMA query_only = ON")
        return self._db_conn

    def close(self):
        """Closes the SQLite connection to prevent memory leaks and file locks."""
        if self._db_conn:
            try:
                self._db_conn.close()
            except Exception as e:
                print(f"⚠️ Error closing DB: {e}")
            finally:
                self._db_conn = None

    def _init_db(self):
        try:
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
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                print("⚠️ DB is locked, skipping init_db for this cycle")
            else:
                raise e

    def add_ioc_node(self, ioc_value: str, ioc_type: str, confidence: float, source: str, conn=None):
        """Adds or updates an IOC node with Bayesian confidence fusion."""
        now = datetime.now(timezone.utc).isoformat()
        
        if self.graph.has_node(ioc_value):
            node_data = self.graph.nodes[ioc_value]
            old_conf = node_data.get("confidence", 0.5)
            # Bayesian Fusion: 1 - (1-p1)(1-p2)
            # Capping at 0.999 to avoid "suspicious" 100% and account for margin of error
            new_conf = min(0.999, 1 - (1 - old_conf) * (1 - confidence))
            
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
        db = conn or self._get_db_conn()
        needs_commit = False
        if not conn:
            db.execute("BEGIN")
            needs_commit = True

        row = db.execute("SELECT provenance FROM node_metadata WHERE node_id = ?", (ioc_value,)).fetchone()
        if row:
            prov = json.loads(row[0])
            if source not in prov:
                prov.append(source)
                db.execute("UPDATE node_metadata SET provenance = ? WHERE node_id = ?", (json.dumps(prov), ioc_value))
        else:
            db.execute("INSERT INTO node_metadata (node_id, provenance) VALUES (?, ?)", 
                         (ioc_value, json.dumps([source])))
        
        if needs_commit:
            db.execute("COMMIT")

    def add_relationship(self, source_id: str, target_id: str, edge_type: str, weight: float, context_id: str, conn=None):
        """Adds a weighted edge scoped to a context_id (e.g. article URL hash)."""
        now = datetime.now(timezone.utc).isoformat()
        
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
            
            db = conn or self._get_db_conn()
            needs_commit = False
            if not conn:
                db.execute("BEGIN")
                needs_commit = True

            db.execute("""
                INSERT OR IGNORE INTO edge_provenance (source, target, edge_key, context_id, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (source_id, target_id, edge_id, context_id, now))
            
            if needs_commit:
                db.execute("COMMIT")

    def enrich_co_occurrence(self, ioc_values: List[str], context_id: str, conn=None):
        """Creates CO_OCCURS_WITH edges between IOCs that appear in the same context."""
        if len(ioc_values) < 2:
            return
        
        # Combinatorial explosion guard
        if len(ioc_values) > 5:
            return

        for i in range(len(ioc_values)):
            for j in range(i + 1, len(ioc_values)):
                self.add_relationship(
                    ioc_values[i], ioc_values[j], 
                    "CO_OCCURS_WITH", 0.5, context_id, 
                    conn=conn
                )

    def apply_decay(self, now: datetime, halflife_days: float = 30):
        """Decays non-reviewed nodes based on wall-clock time."""
        for node, data in self.graph.nodes(data=True):
            # Skip context nodes and reviewed nodes
            if data.get("type") == "context" or data.get("reviewed", False):
                continue
            
            last_seen_str = data.get("last_seen")
            if not last_seen_str:
                continue
                
            last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
            elapsed_hours = (now - last_seen).total_seconds() / 3600
            
            decay_factor = 0.5 ** (elapsed_hours / (halflife_days * 24))
            data["confidence"] = max(0.01, data.get("confidence", 0.5) * decay_factor)

        # Also decay edges? (Skip edges linked to context nodes for cleaner logic)
        for u, v, k, data in self.graph.edges(data=True, keys=True):
            if self.graph.nodes[u].get("type") == "context" or self.graph.nodes[v].get("type") == "context":
                continue
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
            
        # Filter out context nodes from the ranking list (we want the top *IOCs*)
        # but we will bring Article nodes back during subgraph construction to maintain connectivity
        ioc_nodes = [node for node, data in self.graph.nodes(data=True) if data.get("type") != "context"]
        
        if not ioc_nodes:
            return []

        import math
        # Centrality metric: Rewards high confidence exponentially, degree logarithmically
        # (confidence ** 2) * log1p(degree)
        centrality = {
            node: (self.graph.nodes[node].get("confidence", 0) ** 2) * math.log1p(self.graph.degree(node))
            for node in ioc_nodes
        }
        
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
        if not self.read_only:
            self._init_db()
            
        try:
            with self._get_db_conn() as conn:
                cursor = conn.execute("SELECT node_id, reviewed FROM node_metadata")
                for node_id, reviewed in cursor:
                    if self.graph.has_node(node_id):
                        self.graph.nodes[node_id]["reviewed"] = bool(reviewed)
        except sqlite3.OperationalError:
            # If DB is locked or doesn't exist yet, it's fine for load()
            pass
        
        print(f"✅ Graph loaded: {len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges")

    def update_from_batch(self, normalized_iocs: List[Dict], context_id: str):
        """Orchestrates updating nodes and edges from a single article batch."""
        conn = self._get_db_conn()
        ioc_values = []
        
        try:
            # Start transaction manually
            conn.execute("BEGIN")
            
            # Create a 'Context' node for the article to reduce edge explosion
            # Instead of a clique of sized N, we make a star of size N
            # Marking as context so it's ignored by the UI and Bayesian accumulation
            # Added timestamps to context nodes just in case they are ever accessed via Neighborhood query
            now = datetime.now(timezone.utc).isoformat()
            self.graph.add_node(
                context_id, 
                type="context", 
                confidence=0.1, # Reduced to ignore in UI scoring/ranking
                label="Article/Feed Entry", 
                first_seen=now, 
                last_seen=now
            )
            
            for ioc in normalized_iocs:
                val = ioc.get("ioc")
                if not val: continue
                
                self.add_ioc_node(
                    ioc_value=val,
                    ioc_type=ioc.get("type", "unknown"),
                    confidence=ioc.get("fused_confidence", 0.5),
                    source=ioc.get("feed", "unknown"),
                    conn=conn
                )
                ioc_values.append(val)
                
                # Link each IOC to the article context
                w1 = self.graph.nodes[val].get("confidence", 0.5)
                self.add_relationship(val, context_id, "MENTIONED_IN", w1, context_id, conn=conn)
            
            # Enrich with co-occurrence relationships (max 5 IOCs)
            self.enrich_co_occurrence(ioc_values, context_id, conn=conn)
                
            conn.execute("COMMIT")
        except Exception as e:
            conn.execute("ROLLBACK")
            print(f"❌ Rollback in update_from_batch: {e}")
            raise e
