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

### **Phase 3: Temporal Campaign Detection**

**Status:** Completed & Deployed  
**Core Features:**

- **Louvain Community Detection**: Applies the Louvain algorithm on an IOC-only graph projection (context nodes excluded), detecting coordinated threat clusters.
- **Temporal Enrichment**: Tracks `first_seen`, `last_seen`, and `duration_hours` per campaign from Knowledge Graph node timestamps.
- **Campaign Filtering**: Discards trivial communities (< 3 IOCs) to reduce noise. Auto-generates labels from dominant IOC type + date.
- **MongoDB Persistence**: Stores detected campaigns with severity distribution, confidence stats, and IOC membership.
- **Campaign API**: Four new REST endpoints — list, detail, stats, and timeline — with rate limiting and pagination.
- **Scheduler Integration**: Campaign detection runs every 30 minutes via `job_detect_campaigns()`.
- **Test Suite**: 18 tests covering community detection, temporal enrichment, filtering, labeling, timeline generation, and model serialization.

### **Phase 4: Agentic Predictive GraphRAG (Threat Forecasting)**

**Status:** Completed & Deployed  
**Core Features:**

- **GraphContextRetriever**: Traverses the Knowledge Graph to extract IOC neighborhoods, temporal context, severity distributions, and co-occurrence patterns for each campaign.
- **MITRE ATT&CK RAG Integration**: Queries ChromaDB-backed MITRE ATT&CK embeddings to retrieve relevant techniques based on campaign IOC types and severity profiles.
- **3-Step Agentic LLM Pipeline**:
  1. **Stage Classification**: Classifies the campaign's current MITRE ATT&CK kill chain stage.
  2. **Graph-Informed Reasoning**: Uses KG neighbors + MITRE context to reason about the attacker's next logical move.
  3. **Probabilistic TTP Prediction**: Outputs top-3 predicted next MITRE ATT&CK techniques with confidence scores and defensive recommendations.
- **Graceful Degradation**: Falls back to kill-chain-based predictions when Ollama is unavailable.
- **Prediction API**: Three new REST endpoints — `POST /api/predict/campaign/{id}`, `GET /api/predict/stats`, `GET /api/predict/history/{id}` — with 2/min rate limiting.
- **MongoDB Persistence**: Stores predictions in a `predictions` collection with deterministic IDs for deduplication.
- **Scheduler Integration**: TTP prediction runs every 60 minutes via `job_predict_ttps()` for active campaigns.
- **Test Suite**: 25 tests covering models, graph traversal, JSON extraction, fallback predictions, and full pipeline integration with mocked LLM.

### **Phase 5: Evaluation Framework**

**Status:** Completed & Deployed  
**Core Features:**

- **Ground-Truth Labeled Dataset**: 122 curated samples across all 9 IOC types (IP, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, CVE) with four categories: true positives, true negatives, obfuscated IOCs, and edge cases. JSON persistence with load/save/filter support.
- **Metrics Engine**: Computes Precision, Recall, and F1 Score at both aggregate and per-IOC-type levels. Includes confusion matrix counts, confidence calibration (avg TP vs FP confidence), and per-category accuracy tracking.
- **Latency Benchmarking**: Measures per-stage timing (deobfuscation, regex extraction, LLM verification, end-to-end) with min/max/mean/median/p95/p99 percentiles and throughput (samples/sec).
- **Evaluation Orchestrator**: Runs the full extraction pipeline against ground-truth data, computes metrics, benchmarks, and persists results to MongoDB (`evaluations` collection) with deterministic report IDs.
- **Evaluation API**: Four new REST endpoints — `POST /api/evaluation/run`, `GET /api/evaluation/results`, `GET /api/evaluation/history`, `POST /api/evaluation/benchmark` — with rate limiting.
- **Dashboard Component**: SOC-grade evaluation view with F1/Precision/Recall stat cards, confusion-matrix summary, per-type performance table, latency benchmark charts, and evaluation history timeline.
- **Scheduler Integration**: Evaluation runs every 6 hours via `job_run_evaluation()` using the existing `safe_run()` pattern.
- **Test Suite**: 54 tests covering ground-truth dataset validation, metrics computation, latency benchmarking, evaluator integration, edge cases, and data model serialization.
