# Project Roadmap

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

### **Phase 2: Live-Feed Knowledge Graph**

**Status:** Completed & Deployed  
**Core Features:**

- **Knowledge Graph Engine**: Implemented using `NetworkX` with high-performance SQLite metadata persistence.
- **Star Topology Optimization**: **O(N)** relationship mapping (IOC → Article) replacing **O(N^2)** cliques, reducing edge bloat.
- **Bayesian Confidence Fusion**: Continuously updates IOC reliability scores across multiple intelligence feeds.
- **Path Consistency Guard**: Unified data persistence layer ensuring consistency between parser and database writer.
- **Advanced Graph with D3 Physics**: Implemented collision detection, simulation warmup, and interactive controls (Physics Freeze, Connectivity Filter).
- **Feed Milestone**: Expanded coverage to **109+** open-source and professional threat intelligence sources.
- **Visual Overhaul**: Standardized Lucide `Network` iconography and implemented a high-contrast SOC-grade dark theme.
- **API Guardrails**: Enforced 300-node subgraph limits to ensure dashboard stability even with massive datasets.

## Upcoming Phases (To Be Implemented)

### **Phase 3: Temporal Campaign Detection (Current Focus)**

**Goal**: Detect coordinated campaigns by analyzing IOC occurrences over time.

- **Temporal Analysis**: Track "first seen" and "last seen" timestamps per campaign.
- **Community Detection**: Use Louvain/Leiden algorithms to find clusters of related activity.
- **Campaign API**: Endpoints to retrieve and visualize campaigns.

### **Phase 4: GraphRAG-Enhanced Summarization**

**Goal**: Use the Knowledge Graph to provide context-aware summaries.

- **Context Retrieval**: Fetch related graph nodes (e.g., "This IP is linked to Actor X").
- **RAG Integration**: Inject graph context into LLM prompts for deeper analysis.
- **Enhanced Reports**: Summaries that explain _why_ an IOC is dangerous, not just _that_ it is.

### **Phase 5: Evaluation Framework**

**Goal**: Measure the accuracy and performance of the system.

- **Labeled Dataset**: Create a ground-truth dataset of 100-200 malware samples.
- **Metrics Engine**: Calculate Precision, Recall, and F1 scores for extraction.
- **Latency Benchmarking**: Track extraction speed and LLM overhead.
