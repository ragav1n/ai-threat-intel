## AI-Powered Threat Intelligence Aggregator

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![MongoDB](https://img.shields.io/badge/Database-MongoDB-success)
![Ollama](https://img.shields.io/badge/LLM-Ollama%20%7C%20LLaMA3-critical)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED)
![FastAPI](https://img.shields.io/badge/API-FastAPI-009688)

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/ragav1n/ai-threat-intel.git
cd ai-threat-intel
make install

# Run API server
make run-api          # http://localhost:8000

# Run Dashboard (optional, requires Node.js)
cd soc-dashboard && npm run dev  # http://localhost:3000

# Run feed scheduler (in another terminal)
make run-scheduler

# Or use Docker (Recommended for full stack)
make docker-up
```

### Access Points
- **SOC Dashboard**: [http://localhost:3000](http://localhost:3000)
- **API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **API Health**: [http://localhost:8000/health](http://localhost:8000/health)

---

## Overview

A **modular, AI-powered Threat Intelligence Feed Aggregator** that:

* Fetches threat intel from trusted RSS/GitHub/government sources
* Extracts Indicators of Compromise (IOCs) with proper validation
* Normalizes and stores them in MongoDB
* Tracks source health and failures
* Generates human-like summaries using **LLMs (Ollama / LLaMA3)**
* Sends IOC alerts and system health via **email**

---

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **IOC Extraction** | IP (validated), IPv6, Domain, URL, MD5, SHA1, SHA256 |
| 🤖 **AI Summarization** | LLaMA3-powered threat analysis with severity scoring |
| 🕵️ **Hunter Agent** | Auto-enriches IPs with geolocation and domains with WHOIS |
| 📡 **Feed Collection** | Concurrent fetching with health tracking |
| 🔒 **Rate Limiting** | API protected against abuse (10 req/min) |
| 🐳 **Docker Ready** | One-command deployment |
| 📧 **Email Alerts** | Automated notifications with IOC summaries |

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   RSS Feeds     │────▶│   Collector      │────▶│   IOC Extractor │
│   GitHub Atom   │     │   (concurrent)   │     │   (validated)   │
│   CISA Alerts   │     └──────────────────┘     └────────┬────────┘
└─────────────────┘                                       │
                                                          ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Email Alert   │◀────│   Summarizer     │◀────│    MongoDB      │
│   (with IOCs)   │     │   (LLaMA3)       │     │    Storage      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                                                          ▼
                                                 ┌─────────────────┐
                                                 │   REST API      │
                                                 │   (FastAPI)     │
                                                 └─────────────────┘
```

---

## API Reference

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| `/` | GET | Health check | - |
| `/health` | GET | Detailed health | - |
| `/api/summarize` | POST | Analyze IOC | 10/min |
| `/api/summaries` | GET | Get recent summaries | 30/min |
| `/api/trigger-feed` | POST | Manual feed trigger | 2/min |

### Example

```bash
curl -X POST http://localhost:8000/api/summarize \
  -H "Content-Type: application/json" \
  -d '{"ioc": "8.8.8.8", "model": "qwen2.5:7b"}'
```

**Response:**
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "input": "8.8.8.8",
  "summary": "Google Public DNS server...",
  "severity": "Low",
  "enrichment": "[Hunter] IP detected: 8.8.8.8 Geolocation: Mountain View, CA, US. Org: Google LLC."
}
```

---

## Feed Configuration

Edit `threat_intel_aggregator/feed_collection/feeds.yaml`:

```yaml
feeds:
  - name: Cisco Talos
    url: https://blog.talosintelligence.com/rss/
    category: malware analysis
    source_type: blog

  - name: CISA Alerts
    url: https://us-cert.cisa.gov/ncas/all.xml
    category: official alerts
    source_type: government
```

---

## Commands

| Command | Description |
|---------|-------------|
| `make install` | Install dependencies |
| `make run-api` | Start API server |
| `make run-scheduler` | Start feed scheduler |
| `make docker-up` | Start with Docker Compose |
| `make docker-down` | Stop Docker services |
| `make clean` | Clean cache files |

---

## Environment Variables

Create a `.env` file:

```env
MONGO_URI=mongodb://localhost:27017/
MONGO_DB=threat_intel
API_PORT=8000
SCHEDULER_INTERVAL=10
LOG_LEVEL=INFO
```

---

## Project Structure

```
ai-threat-intel/
├── config.py                    # Centralized configuration
├── unified_api_server.py        # FastAPI server
├── Dockerfile                   # Container definition
├── docker-compose.yml           # Multi-service setup
├── Makefile                     # Development commands
├── requirements.txt             # Python dependencies
├── threat_intel_aggregator/     # Feed collection module
│   ├── main.py                  # Scheduler entrypoint
│   ├── enums.py                 # IOC types & severity
│   └── feed_collection/         # Feed processing
└── threat_model/                # AI summarization module
    ├── hunter.py                # IOC enrichment agent
    └── threat_summarizer/       # LLM integration
```

---

## Contributors

* **Saara Unnathi R** — Feed Collection · IOC Parsing
* **N Ragavenderan** — IOC Parsing · AI Summarization · Pipeline Orchestration

---
