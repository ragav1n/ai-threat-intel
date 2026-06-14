# Threat Intelligence Aggregator

The ingestion and analytics package. It collects indicators of compromise
(IOCs) from open sources, deobfuscates and extracts them, verifies them with a
local LLM, and feeds the downstream knowledge graph, campaign detection,
prediction, and evaluation modules.

## Components

| Module | Responsibility |
| :--- | :--- |
| `feed_collection/` | Fetch, parse, deobfuscate, extract, verify, and store IOCs |
| `knowledge_graph/` | Build and query the IOC / campaign / technique graph |
| `campaign_detector/` | Group indicators into campaigns via community detection on the graph |
| `predictive_graphrag/` | Forecast likely next techniques with a graph-informed LLM pipeline |
| `evaluation/` | Calibration, conformal, adversarial, and baseline studies |

---

## Feed collection pipeline

`feed_collection/` is the core ingestion path:

1. **Collect** (`collector.py`) — fetches configured sources concurrently with
   retries and exponential backoff. `github_discovery.py` auto-discovers Atom
   feeds from security repositories.
2. **Parse** (`parser.py`) — normalizes RSS/Atom, JSON, CSV, and text into a
   common record schema.
3. **Deobfuscate** (`ioc_deobfuscator.py`) — reverses defanging, character
   encoding, homoglyph, and zero-width disguises before extraction.
4. **Extract** (`ioc_extractor.py`) — regex extraction of IPs, domains, URLs,
   hashes, CVEs, and emails with a per-candidate confidence score.
5. **Verify** (`llm_ioc_verifier.py`, `llm_providers.py`) — a local Ollama
   model judges each candidate; `confidence_fusion.py` combines the regex and
   LLM scores into one fused confidence.
6. **Store** (`mongo_writer.py`) — writes deduplicated IOCs to MongoDB
   (`type::value` SHA-256 key) and exports `data/normalized_iocs.{json,csv}`.

`health.py` and `status.py` track per-feed uptime, response time, and success
rate, and trigger an email alert after three consecutive failures.

---

## Layout

```plaintext
threat_intel_aggregator/
├── main.py                      # Collection entry point / scheduler
├── enums.py                     # IOC type and severity definitions
├── feed_collection/
│   ├── collector.py             # Concurrent fetch + retry
│   ├── github_discovery.py      # GitHub feed auto-discovery
│   ├── parser.py                # Normalization
│   ├── ioc_deobfuscator.py      # Defang / homoglyph / encoding reversal
│   ├── ioc_extractor.py         # Regex extraction + scoring
│   ├── llm_ioc_verifier.py      # Local LLM verification
│   ├── llm_providers.py         # Ollama / cloud verifier backends
│   ├── confidence_fusion.py     # Regex + LLM score fusion
│   ├── mongo_writer.py          # Storage + deduplication
│   ├── health.py / status.py    # Feed health tracking
│   ├── config.py                # Configuration loader
│   └── feeds.yaml               # Feed definitions (102 sources)
├── knowledge_graph/             # graph_manager.py
├── campaign_detector/           # detector.py, temporal.py, models.py
├── predictive_graphrag/         # graph_traversal.py, ttp_predictor.py
├── evaluation/                  # Research evaluation harness
└── data/                        # Local outputs and feed health state
```

---

## Setup

```bash
cd threat_intel_aggregator
pip install -r requirements.txt
```

Requires Python 3.11+, a running MongoDB, and Ollama for verification.

Configuration is read from the repository-root `.env` (see the main README);
the relevant keys here are `MONGO_URI`, `MONGO_DB`, `OLLAMA_URL`, and
`IOC_VERIFIER_MODEL` (default `qwen3.5:9b`). Feed sources are edited in
`feed_collection/feeds.yaml`:

```yaml
feeds:
  - name: "CISA US-CERT"
    url: "https://www.us-cert.gov/ncas/alerts.xml"
    source_type: "rss"
    category: "government"
```

---

## Usage

```bash
python main.py          # run once on startup, then every SCHEDULER_INTERVAL minutes
```

Press `Ctrl+C` to stop. Logs are written to `data/feed_collector.log`.

### Outputs

| File | Description |
| :--- | :--- |
| `data/normalized_iocs.json` | All IOCs from the last run |
| `data/normalized_iocs.csv` | CSV export (used for email attachments) |
| `data/feed_health.json` | Per-feed last success/failure and response time |
| `../threat_model/input.txt` | IOC list handed to the summarizer |

---

## Evaluation

`evaluation/` holds the research code behind the project's IOC-extraction
study: obfuscation generation and ablation, calibration and conformal risk
control, adversarial attack/defense generators, baseline comparison against
off-the-shelf extractors, and bootstrap confidence intervals. The reproducible
runs and recorded numbers live in `../scripts/` and `../RESULTS.md`.
