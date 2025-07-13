from pathlib import Path
from datetime import datetime
from .model_client import query_ollama
from .logger import log_summary

TEMPLATE_PATH = Path(__file__).parent / "prompt_template.txt"
SEVERITY_TEMPLATE_PATH = Path(__file__).parent / "severity_template.txt"

def load_prompt_template(path) -> str:
    return Path(path).read_text()

def format_template(threat_input: str, path: Path) -> str:
    template = load_prompt_template(path)
    return template.replace("{{INPUT}}", threat_input)

def summarize_threat(threat_input: str, model: str = "llama2") -> dict:
    summary_prompt = format_template(threat_input, TEMPLATE_PATH)
    severity_prompt = format_template(threat_input, SEVERITY_TEMPLATE_PATH)

    summary = query_ollama(model, summary_prompt)
    severity = query_ollama(model, severity_prompt)

    log_summary(threat_input, summary, severity)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "input": threat_input,
        "summary": summary,
        "severity": severity
    }
