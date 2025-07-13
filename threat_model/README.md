# 🛡️ Threat Model: AI-Powered Threat Summarization System

This system uses local LLMs via [Ollama](https://ollama.com) to generate professional threat summaries from raw inputs (IOCs, URLs, indicators), estimate and validate severity, and log results with full export and alert capabilities. Built as a modular, extensible backend component.

---

## 🚀 Features

- 🔐 Summarizes threat inputs using local LLaMA2 via Ollama
- 📊 Estimates and validates severity (Low / Medium / High)
- 🧠 Auto-corrects misclassified severities
- 📝 Logs results to CSV, JSON, JSONL, MongoDB
- 📧 Batches and sends alert emails with:
  - Rich HTML report
  - PDF summary report
  - Attached CSV/JSON logs
- ⏰ Supports timer-based alerting (e.g., every 10 minutes)

---

## 🧰 Requirements

- Python 3.8+
- Ollama (installed and running with `llama2`)
- MongoDB Atlas (or local Mongo)
- Gmail App Password (for SMTP email sending)
- `pip install -r requirements.txt`

---

## 📁 Project Structure

threat_model/
├── input.txt # Raw IOCs go here
├── output.txt # Saved plain summaries
├── processed_inputs.txt # Tracks seen IOCs
│
├── logs/
│ ├── summaries.csv
│ ├── summaries.json
│ ├── summaries.jsonl
│ └── threat_summary_report.pdf
│
├── threat_summarizer/
│ ├── init.py
│ ├── summarizer.py
│ ├── validator.py
│ ├── logger.py
│ ├── model_client.py
│ ├── mongo_client.py
│ ├── emailer.py
│ ├── pdf_generator.py
│ ├── prompt_template.txt
│ ├── severity_template.txt
│ └── watch_and_run.py
│
├── .env # Mongo and email credentials
├── setup.py
├── requirements.txt
└── README.md

---

## 🔧 Setup

### 1. Install Ollama + LLaMA 2

```bash
brew install ollama
ollama run llama2
```

Leave Ollama running in one terminal window.

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### ▶️ How to Use

# Run the Watcher:

```bash
cd threat_model
python3 -m threat_summarizer.watch_and_run
```

This will:

- Process each new IOC
- Generate summaries
- Validate severity
- Log results
- Batch High severity threats
- Send email alerts every 10 threats or 10 minutes

### 📦 Output

# Per IOC:
    - output.txt updated
    - logs/ updated
    - MongoDB collection updated

# Email:
    - HTML summary of high severity IOCs
    - PDF report attached
    - CSV + JSON attached

---

### 📄 License

MIT License