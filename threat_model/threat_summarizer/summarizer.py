from pathlib import Path
from datetime import datetime
from .model_client import query_ollama

TEMPLATE_PATH = Path(__file__).parent / "prompt_template.txt"
SEVERITY_TEMPLATE_PATH = Path(__file__).parent / "severity_template.txt"

def load_prompt_template(path) -> str:
    return Path(path).read_text()

def format_template(threat_input: str, path: Path) -> str:
    template = load_prompt_template(path)
    return template.replace("{{INPUT}}", threat_input)

def clean_severity_output(raw_output: str) -> str:
    for level in ["Low", "Medium", "High"]:
        if level.lower() in raw_output.lower():
            return level
    return "Unknown"

from threat_model.hunter import enrich_ioc

def summarize_threat(threat_input: str, model: str = "llama3.2:latest") -> dict:
    # 🕵️‍♂️ Hunter Agent Enrichment
    enrichment_data = enrich_ioc(threat_input)
    
    # Append enrichment to the input for the context of LLM
    full_input_context = f"{threat_input}\n\n[NETWORK INTELLIGENCE]:\n{enrichment_data}"
    
    summary_prompt = format_template(full_input_context, TEMPLATE_PATH)
    severity_prompt = format_template(full_input_context, SEVERITY_TEMPLATE_PATH)

    summary = query_ollama(model, summary_prompt)
    severity_raw = query_ollama(model, severity_prompt)
    severity = clean_severity_output(severity_raw)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "input": threat_input,
        "summary": summary,
        "severity": severity
    }
