# 🛡️ Threat Intelligence Feed Aggregator

A fully automated, production-grade threat intelligence feed aggregator that:
- Collects threat indicators (IOCs) from RSS, Atom, YAML-based feeds
- Normalizes and stores them in MongoDB (deduplicated)
- Writes IOCs to `input.txt` for downstream processing (e.g., AI summarization)
- Tracks feed health, logs failures, and sends email alerts
- Supports fault tolerance, scheduling, and real-time monitoring

---

## 📂 Project Structurethreat_intel_aggregator/
├── main.py # Entry point with scheduler
├── data/ # Stores JSON, CSV, logs, timestamps
│ ├── normalized_iocs.json
│ ├── normalized_iocs.csv
│ ├── feed_collector.log
│ └── ...
├── feed_collection/
│ ├── collector.py # Feed fetching & concurrency
│ ├── parser.py # Feed parsing & extraction
│ ├── ioc_extractor.py # IOC regex extraction
│ ├── mongo_writer.py # MongoDB insert & export to input.txt
│ ├── config.py # Loads feeds.yaml & paths
│ ├── feeds.yaml # Feed configuration list
│ └── summarizer.py (optional) # If integrated directly with Ollama
├── .env # Mongo URI & config (not committed)
└── requirements.txt # Python dependencies

---

## 🚀 Features

- ✅ Concurrent feed fetching from any RSS/Atom/CSV/JSON feeds
- ✅ Custom IOC extraction: IPs, domains, hashes, URLs, etc.
- ✅ Deduplication using SHA256 hash-based `_id`
- ✅ Feed health tracking (success/failure, timestamps)
- ✅ Outputs IOCs as `.json`, `.csv`, and bullet-formatted `input.txt`
- ✅ Email alert system with uptime, IOC count, and CSV attachment
- ✅ Watchdog loop with crash recovery

---

## 🔧 Installation

### 1. Clone the repo and install dependencies:

```bash
git clone https://github.com/your-org/threat_intel_aggregator.git
cd threat_intel_aggregator

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### ▶️ Running the Aggregator

```bash
cd threat_intel_aggregator
python3 main.py
```

- Starts with an immediate IOC fetch
- Then runs every 10 minutes
- Writes logs to data/feed_collector.log
- Fails gracefully with retries and alerting

### 🔁 Output Files

| File                   | Description                          |
| ---------------------- | ------------------------------------ |
| `normalized_iocs.json` | Clean list of extracted IOCs         |
| `normalized_iocs.csv`  | Same in CSV format                   |
| `feed_health.json`     | Status of each feed                  |
| `input.txt`            | Bullet-formatted IOCs for summarizer |
| `feed_collector.log`   | Full log file                        |

### 📬 Alert System

If 3 consecutive cycles fail:

- Sends an email with reason
- Includes:
    - Uptime duration
    - IOC count and sample
    - Formatted ASCII table of IOCs
    - Attached .csv report

### Integration: Threat Summarizer

This aggregator writes input.txt to a separate module:

```bash

../threat_model/input.txt
```

Your summarizer can monitor this file and:

    - Summarize IOCs via Ollama

    - Store the summary in MongoDB

    - Send out PDF or HTML reports

---

## 📝 License

MIT License
