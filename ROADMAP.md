# Project Roadmap & Status

This document tracks the high-level implementation status of the AI Threat Intelligence project, bridging the gap between completed work and future phases.

## Completed Phases

### **Phase 1: Hybrid LLM + Regex IOC Extraction**
**Status:** Completed & Deployed  
**Core Features:**
- **Hybrid Extraction Pipeline**: Combines regex-based IOC extraction with LLM-powered verification (Ollama `qwen2.5:7b`).
- **Deobfuscation Engine**: Automatically handles obfuscated IOCs (e.g., `hxxp://`, `example[.]com`, Base64 encoded strings).
- **Confidence Fusion**: Sophisticated scoring model (0.4×Regex + 0.6×LLM) with penalties for LLM-rejected IOCs.
- **REST API Enhancements**:
    - New `POST /api/iocs/verify` endpoint for on-demand verification.
    - Rate-limited (5/min) to prevent LLM abuse.
- **Security Hardening**:
    - **NoSQL Injection Protection**: Strict input validation and regex anchoring.
    - **Timing-Safe Operations**: Secure comparison for secret keys.
    - **Resource Limits**: Base64 decode limits (2KB) and model allowlists.
- **Infrastructure**:
    - **Database Migration**: Consolidated `threat_intel_db` → `threat_intel` (1800+ IOCs migrated).
    - **Docker Optimization**: Fully containerized deployment with health checks.

## Upcoming Phases (To Be Implemented)

### **Phase 2: Live-Feed Knowledge Graph (Current Focus)**
**Goal**: Transform disconnected IOC lists into a connected graph of threat actors, TTPs, and indicators.
-  **Knowledge Graph Engine**: Implement `NetworkX` or `Neo4j` integration.
-  **Schema Definition**: Define node types (IOC, Malware, CVE, Actor) and edge types (related-to, uses, targeting).
-  **Pipeline Integration**: Update feed collector to generate graph edges in real-time.
-  **Graph Visualization**: Interactive graph view in the dashboard.

### **Phase 3: Temporal Campaign Detection**
**Goal**: Detect coordinated campaigns by analyzing IOC occurrences over time.
-  **Temporal Analysis**: Track "first seen" and "last seen" timestamps per campaign.
-  **Community Detection**: Use Louvain/Leiden algorithms to find clusters of related activity.
-  **Campaign API**: Endpoints to retrieve and visualize campaigns.

### **Phase 4: GraphRAG-Enhanced Summarization**
**Goal**: Use the Knowledge Graph to provide context-aware summaries.
-  **Context Retrieval**: Fetch related graph nodes (e.g., "This IP is linked to Actor X").
-  **RAG Integration**: Inject graph context into LLM prompts for deeper analysis.
-  **Enhanced Reports**: Summaries that explain *why* an IOC is dangerous, not just *that* it is.

### **Phase 5: Evaluation Framework**
**Goal**: Measure the accuracy and performance of the system.
-  **Labeled Dataset**: Create a ground-truth dataset of 100-200 malware samples.
-  **Metrics Engine**: Calculate Precision, Recall, and F1 scores for extraction.
-  **Latency Benchmarking**: Track extraction speed and LLM overhead.
