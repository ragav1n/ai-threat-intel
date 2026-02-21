import os
import sys
import json
from typing import List, Dict, Any

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from threat_intel_aggregator.feed_collection.parser import normalize_parsed_results

def test_parser_integration():
    # Create a mock raw feed output
    mock_rss = """
    <rss version="2.0">
        <channel>
            <title>Mock Feed</title>
            <item>
                <title>Article 1</title>
                <link>http://example.com/1</link>
                <summary>Malware found at 1.1.1.1 and 2.2.2.2</summary>
            </item>
            <item>
                <title>Article 2</title>
                <link>http://example.com/2</link>
                <summary>C2 server at example.org</summary>
            </item>
        </channel>
    </rss>
    """
    
    raw_feed_path = "data/raw_feed_output.json"
    os.makedirs("data", exist_ok=True)
    
    with open(raw_feed_path, "w") as f:
        json.dump({
            "MockFeed": {
                "status": "success",
                "url": "http://mockfeed.com/rss",
                "content": mock_rss
            }
        }, f)
        
    captured_updates = []
    
    def mock_kg_callback(iocs, context_id):
        print(f"Callback triggered for context {context_id} with {len(iocs)} IOCs")
        captured_updates.append((context_id, iocs))
        
    print("Running parser...")
    normalize_parsed_results(kg_callback=mock_kg_callback)
    
    print(f"Captured {len(captured_updates)} updates")
    assert len(captured_updates) == 2
    
    # Check first update
    ctx1, iocs1 = captured_updates[0]
    ioc_values = [i["ioc"] for i in iocs1]
    print(f"Entry 1 IOCs: {ioc_values}")
    assert "1.1.1.1" in ioc_values
    assert "2.2.2.2" in ioc_values
    
    # Check second update
    ctx2, iocs2 = captured_updates[1]
    ioc_values2 = [i["ioc"] for i in iocs2]
    print(f"Entry 2 IOCs: {ioc_values2}")
    assert "example.org" in ioc_values2
    
    print("✅ Parser Integration Test Passed!")

if __name__ == "__main__":
    test_parser_integration()
