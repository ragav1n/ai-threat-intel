# Threat Model — Summarizer and Hunter Agent

The analysis package. It enriches IOCs, retrieves relevant MITRE ATT&CK
context, and uses a local LLM to produce a structured summary, a severity
score, and a technique mapping. It runs either interactively or as a watchdog
that processes new IOCs from the aggregator.

## What it does

- **Local LLM analysis** — uses Ollama (default `qwen2.5:7b`), so data stays on
  the host.
- **Hunter agent** (`hunter.py`) — enriches IPs and domains with geolocation,
  WHOIS, ASN, and DNS resolution.
- **MITRE ATT&CK RAG** (`threat_summarizer/mitre_rag.py`) — retrieves relevant
  techniques by semantic search and maps observed behavior to TTPs with
  confidence scores.
- **Reporting** — generates PDF reports (`pdf_generator.py`), CSV exports
  (`exporter.py`), and batched HTML email alerts (`emailer.py`) for high- and
  critical-severity threats.

---

## Pipeline

1. **Input** — an IOC or free-text description from the CLI, or a line from
   `input.txt` (written by `threat_intel_aggregator`).
2. **Enrich** — the Hunter adds network context (GeoIP, ASN, WHOIS, DNS).
3. **Retrieve** — the RAG layer pulls matching MITRE ATT&CK techniques.
4. **Summarize** — the LLM combines enrichment, retrieved context, and the
   prompt templates into a structured result.
5. **Validate and store** — `validator.py` checks the output; results go to
   MongoDB and, for severe threats, into a batched email report.

---

## Layout

```plaintext
threat_model/
├── main.py                      # Interactive CLI
├── main_export.py               # Batch export entry point
├── hunter.py                    # Enrichment agent
├── threat_summarizer/
│   ├── summarizer.py            # Core LLM + RAG logic
│   ├── watch_and_run.py         # Watchdog over input.txt
│   ├── mitre_rag.py             # MITRE ATT&CK retrieval
│   ├── model_client.py          # Ollama client
│   ├── mongo_client.py          # MongoDB access
│   ├── validator.py             # Output validation
│   ├── emailer.py               # Batched email alerts
│   ├── pdf_generator.py         # PDF reports
│   ├── exporter.py              # CSV export
│   ├── logger.py                # Logging setup
│   ├── prompt_template.txt      # Summary prompt
│   ├── severity_template.txt    # Severity-scoring prompt
│   └── ttp_template.txt         # TTP-extraction prompt
└── logs/
```

---

## Setup

```bash
ollama pull qwen2.5:7b
cd threat_model
pip install -r requirements.txt
```

Requires Ollama running and a reachable MongoDB. Configuration is read from the
repository-root `.env` (see the main README).

---

## Usage

### Interactive CLI

```bash
python main.py
```

Enter an IOC (`103.15.5.21`) or a description ("phishing email with a
malicious attachment"); the summary prints to the console.

### Watchdog (pipeline mode)

```bash
python -m threat_summarizer.watch_and_run
```

Monitors `input.txt`, summarizes new entries as they appear, and sends batched
email reports for high- and critical-severity threats.

---

## Output

```json
{
  "timestamp": "2024-02-08T10:00:00+05:30",
  "input": "103.15.5.21",
  "severity": "High",
  "summary": "The IP 103.15.5.21 is associated with Cobalt Strike beaconing...",
  "mitre_ttps": [
    {
      "technique_id": "T1190",
      "technique_name": "Exploit Public-Facing Application",
      "confidence": 0.95
    }
  ],
  "enrichment": "Geolocation: Singapore. Org: DigitalOcean."
}
```
