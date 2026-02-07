"""
Threat summarization using LLM with Hunter agent enrichment.
"""
from pathlib import Path
from datetime import datetime
from typing import TypedDict

from .model_client import query_ollama
from threat_model.hunter import enrich_ioc

# Import Severity enum - handle both import paths
try:
    from threat_intel_aggregator.enums import Severity
except ImportError:
    # Fallback for when running from different contexts
    from enum import Enum
    class Severity(str, Enum):
        LOW = "Low"
        MEDIUM = "Medium"
        HIGH = "High"
        UNKNOWN = "Unknown"
        
        @classmethod
        def from_string(cls, value: str) -> "Severity":
            value_lower = value.lower()
            for level in cls:
                if level.value.lower() in value_lower:
                    return level
            return cls.UNKNOWN


TEMPLATE_PATH = Path(__file__).parent / "prompt_template.txt"
SEVERITY_TEMPLATE_PATH = Path(__file__).parent / "severity_template.txt"


class ThreatSummaryResult(TypedDict):
    """Type definition for threat summary response."""
    timestamp: str
    input: str
    summary: str
    severity: str
    enrichment: str


def load_prompt_template(path: Path) -> str:
    """Load a prompt template from file."""
    return path.read_text()


def format_template(threat_input: str, path: Path) -> str:
    """Format a template with the threat input."""
    template = load_prompt_template(path)
    return template.replace("{{INPUT}}", threat_input)


def parse_severity(raw_output: str) -> Severity:
    """
    Parse severity level from LLM output.
    Uses the Severity enum for type safety.
    """
    return Severity.from_string(raw_output)


def summarize_threat(
    threat_input: str, 
    model: str = "llama3.2:latest"
) -> ThreatSummaryResult:
    """
    Summarize a threat indicator using LLM with network intelligence enrichment.
    
    Args:
        threat_input: The IOC or threat description to analyze.
        model: The Ollama model to use for summarization.
    
    Returns:
        ThreatSummaryResult with timestamp, input, summary, severity, and enrichment.
    """
    # 🕵️ Hunter Agent Enrichment
    enrichment_data = enrich_ioc(threat_input)
    
    # Build context with enrichment
    full_input_context = f"{threat_input}\n\n[NETWORK INTELLIGENCE]:\n{enrichment_data}"
    
    # Generate prompts
    summary_prompt = format_template(full_input_context, TEMPLATE_PATH)
    severity_prompt = format_template(full_input_context, SEVERITY_TEMPLATE_PATH)

    # Query LLM
    summary = query_ollama(model, summary_prompt)
    severity_raw = query_ollama(model, severity_prompt)
    severity = parse_severity(severity_raw)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "input": threat_input,
        "summary": summary,
        "severity": str(severity),
        "enrichment": enrichment_data,
    }
