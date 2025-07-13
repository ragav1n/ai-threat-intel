# ai-threat-intel
The existing README only contains a title (`# ai-threat-intel`). Let's now create a **comprehensive and hackathon-winning `README.md`** from scratch based on your project structure and functionality.

---

## 🛡️ AI-Powered Threat Intelligence Aggregator

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![MongoDB](https://img.shields.io/badge/Database-MongoDB-success)
![Ollama](https://img.shields.io/badge/LLM-Ollama%20%7C%20LLaMA2-critical)

---

### 📌 Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Architecture](#architecture)
* [How It Works](#how-it-works)
* [Feed Configuration](#feed-configuration)
* [AI Summarization](#ai-summarization)
* [Setup & Installation](#setup--installation)
* [Usage](#usage)
* [Data Flow](#data-flow)
* [Sample Output](#sample-output)
* [Contributors](#contributors)
* [License](#license)

---

## 📖 Overview

This project is a **modular, AI-powered Threat Intelligence Feed Aggregator** that:

* Fetches threat intel from trusted RSS/GitHub/government sources
* Extracts Indicators of Compromise (IOCs)
* Normalizes and stores them in MongoDB
* Tracks source health and failures
* Generates human-like summaries using **LLMs (Ollama / LLaMA2 / Claude)**
* Sends IOC alerts and system health via **email**

---

## 🚀 Features

✅ Feed ingestion from blogs, GitHub, and government alerts
✅ Regex-powered IOC extraction (IP, domain, URL, hash, etc.)
✅ MongoDB persistence for all IOCs
✅ Health tracking + CSV-based historical logging
✅ AI-generated threat summaries via `input.txt` → `watch_and_run.py`
✅ Email notifications with uptime and attachments
✅ Easy YAML-based feed configuration
✅ CLI & Scheduler ready

---

## 🧠 Architecture

```mermaid
graph TD
  A[feeds.yaml] --> B[collector.py]
  B --> C[ioc_extractor.py]
  C --> D[mongo_writer.py]
  D --> E[MongoDB]

  B --> F[health.py]
  F --> G[feed_health.json + CSV]

  D --> H[input.txt]
  H --> I[watch_and_run.py (Ollama LLM)]

  E --> J[Email Alert System]
```

---

## 🔁 How It Works

1. **Feeds** configured in `feeds.yaml`
2. `main.py` schedules periodic collection
3. `collector.py` fetches feeds concurrently
4. `ioc_extractor.py` parses IPs, domains, URLs, hashes
5. Results are normalized and stored in MongoDB
6. Feed health is logged in JSON & CSV
7. IOCs are exported to `input.txt` → AI Summarizer
8. Summaries and critical alerts are emailed to security analysts

---

## ⚙️ Feed Configuration

```yaml
feeds:
  - name: Cisco Talos
    url: https://blog.talosintelligence.com/rss/
    category: malware analysis
    source_type: blog

  - name: GitHub Malware Zoo
    url: https://github.com/ytisf/theZoo/commits/master.atom
    category: malware repo updates
    source_type: github
```

---

## 🧠 AI Summarization

* IOCs are exported to `input.txt`
* A local LLM (via Ollama or Claude) reads the file
* Summarized text is generated in `watch_and_run.py`
* Email alerts include this summary for analyst insight

---

## 💻 Setup & Installation

```bash
# Clone the repo
git clone https://github.com/yourname/ai-threat-intel.git
cd ai-threat-intel/threat_intel_aggregator

# Install dependencies
pip install -r requirements.txt

# Set up MongoDB locally (default URI: mongodb://localhost:27017)

# Add your email credentials to `.env`
EMAIL_SENDER=your_email@gmail.com
EMAIL_PASSWORD=your_app_password
EMAIL_RECIPIENT=recipient@gmail.com
```

---

## ▶️ Usage

```bash
# Run the main pipeline
python main.py

# Run the summarizer (after IOCs are saved)
python watch_and_run.py
```

---

## 📊 Data Flow

* IOC Types Extracted: IP, IPv6, Domain, URL, MD5, SHA1, SHA256
* Stored in MongoDB in `threat_intel_db.iocs`
* Feed health in `feed_health.json` and `feed_health_history.csv`
* Summarizer input: `input.txt`
* Email includes: Summary, IOC count, Uptime

---

## 🧪 Sample Output

```
IOC Summary:
- 35 IP addresses
- 12 Domains
- 5 URLs
- 2 SHA256 hashes

Uptime: 182 minutes
Feed Health: All green ✅
```

---

## 🙋 Contributors

* Saara Unnathi R — Feed Collection · IOC Parsing
* Ragavendaran K — IOC Parsing · AI Summarization · Pipeline Orchestration
* Jahnavi Rai — AI Summarization · UI Rendering
* Khushi Gupta — UI Rendering · Pipeline Orchestration

---
