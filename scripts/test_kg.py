import os
import sys
import json
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from threat_intel_aggregator.knowledge_graph.graph_manager import ThreatKnowledgeGraph

def test_kg_logic():
    data_dir = "data/kg_test"
    if os.path.exists(data_dir):
        import shutil
        shutil.rmtree(data_dir)
    
    kg = ThreatKnowledgeGraph(data_dir=data_dir)
    
    print("--- Test 1: Node Addition and Bayesian Fusion ---")
    kg.add_ioc_node("1.1.1.1", "ip", 0.6, "Feed_A")
    kg.add_ioc_node("1.1.1.1", "ip", 0.7, "Feed_B")
    
    conf = kg.graph.nodes["1.1.1.1"]["confidence"]
    # Expected: 1 - (1-0.6)(1-0.7) = 1 - 0.4*0.3 = 1 - 0.12 = 0.88
    print(f"Confidence for 1.1.1.1: {conf:.4f} (Expected: 0.8800)")
    assert abs(conf - 0.88) < 0.001
    
    print("--- Test 2: Relationships and Context Scoping ---")
    kg.add_relationship("1.1.1.1", "example.com", "CO_OCCURS_WITH", 0.8, "Article_1")
    kg.add_relationship("1.1.1.1", "example.com", "CO_OCCURS_WITH", 0.9, "Article_1") # Duplicate, should be filtered or updated?
    # Our implementation uses MultiDiGraph with key="CO_OCCURS_WITH:Article_1", so it's stable.
    
    print(f"Edges: {len(kg.graph.edges)}")
    assert len(kg.graph.edges) == 1
    
    print("--- Test 3: Decay Logic ---")
    # Set back the timestamp of 1.1.1.1 to 30 days ago
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    kg.graph.nodes["1.1.1.1"]["last_seen"] = thirty_days_ago.isoformat()
    
    now = datetime.now(timezone.utc)
    kg.apply_decay(now, halflife_days=30)
    
    decayed_conf = kg.graph.nodes["1.1.1.1"]["confidence"]
    # Expected: 0.88 * 0.5 = 0.44
    print(f"Decayed confidence: {decayed_conf:.4f} (Expected: 0.44)")
    assert abs(decayed_conf - 0.44) < 0.01

    print("--- Test 4: Persistence ---")
    kg.persist()
    assert os.path.exists(os.path.join(data_dir, "graph.json"))
    assert os.path.exists(os.path.join(data_dir, "kg_metadata.db"))
    
    kg2 = ThreatKnowledgeGraph(data_dir=data_dir)
    print(f"Loaded nodes: {len(kg2.graph.nodes)}")
    assert len(kg2.graph.nodes) == 2 # 1.1.1.1 and example.com (auto-added by relationship if needed, wait...)
    # Actually add_relationship doesn't auto-add nodes in my simple implementation if they don't exist?
    # NetworkX add_edge auto-adds nodes if they don't exist.
    
    print("✅ All Graph Logic Tests Passed!")

if __name__ == "__main__":
    test_kg_logic()
