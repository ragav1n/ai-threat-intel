"""
Threat summarization using LLM with Hunter agent enrichment.
Enhanced with MITRE ATT&CK mapping and structured output.
"""
from pathlib import Path
from datetime import datetime
from typing import TypedDict, Optional, List

from .model_client import query_ollama
from threat_model.hunter import enrich_ioc

# Import Severity enum - handle both import paths
try:
    from threat_intel_aggregator.enums import Severity
except ImportError:
    from enum import Enum
    class Severity(str, Enum):
        LOW = "Low"
        MEDIUM = "Medium"
        HIGH = "High"
        CRITICAL = "Critical"
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
    mitre_tactics: Optional[List[str]]
    recommendations: Optional[List[str]]


def load_prompt_template(path: Path) -> str:
    """Load a prompt template from file."""
    return path.read_text()


def format_template(threat_input: str, path: Path) -> str:
    """Format a template with the threat input."""
    template = load_prompt_template(path)
    return template.replace("{{INPUT}}", threat_input)


def parse_severity(raw_output: str) -> Severity:
    """Parse severity level from LLM output."""
    return Severity.from_string(raw_output)


def extract_mitre_tactics(summary: str) -> List[str]:
    """
    Extract potential MITRE ATT&CK tactics from the summary.
    Basic keyword matching - could be enhanced with LLM.
    """
    tactics_keywords = {
        "Initial Access": ["phishing", "exploit", "drive-by", "spearphishing", "supply chain"],
        "Execution": ["script", "powershell", "cmd", "macro", "malware execution"],
        "Persistence": ["registry", "scheduled task", "startup", "backdoor", "implant"],
        "Privilege Escalation": ["elevation", "privilege", "root", "admin", "sudo"],
        "Defense Evasion": ["obfuscation", "encryption", "packed", "disguised", "evasion"],
        "Credential Access": ["password", "credential", "keylog", "brute force", "hash"],
        "Discovery": ["reconnaissance", "scanning", "enumeration", "discovery"],
        "Lateral Movement": ["lateral", "spread", "propagat", "remote", "psexec"],
        "Collection": ["exfiltrat", "data theft", "screenshot", "clipboard", "keylog"],
        "Command and Control": ["c2", "c&c", "beacon", "callback", "botnet", "rat"],
        "Exfiltration": ["exfiltrat", "data transfer", "upload", "steal"],
        "Impact": ["ransomware", "encrypt", "wipe", "destroy", "denial of service", "ddos"],
    }
    
    found_tactics = []
    summary_lower = summary.lower()
    
    for tactic, keywords in tactics_keywords.items():
        if any(kw in summary_lower for kw in keywords):
            found_tactics.append(tactic)
    
    return found_tactics[:5]  # Limit to top 5


def extract_recommendations(summary: str) -> List[str]:
    """Extract actionable recommendations from the summary."""
    recommendations = []
    
    # Look for numbered items or bullet points
    lines = summary.split('\n')
    in_recommendations = False
    
    for line in lines:
        line = line.strip()
        if 'recommend' in line.lower() or 'action' in line.lower() or 'response' in line.lower():
            in_recommendations = True
            continue
        
        if in_recommendations and line:
            # Clean up the line
            if line[0].isdigit() or line.startswith('-') or line.startswith('•'):
                clean = line.lstrip('0123456789.-•) ').strip()
                if len(clean) > 10:  # Skip very short items
                    recommendations.append(clean)
    
    return recommendations[:5]  # Limit to 5


def summarize_threat(
    threat_input: str, 
    model: str = "qwen2.5:7b",
    include_enrichment: bool = True
) -> ThreatSummaryResult:
    """
    Summarize a threat indicator using LLM with network intelligence enrichment.
    
    Args:
        threat_input: The IOC or threat description to analyze.
        model: The Ollama model to use for summarization.
        include_enrichment: Whether to include Hunter enrichment.
    
    Returns:
        ThreatSummaryResult with full analysis.
    """
    # Hunter Agent Enrichment
    enrichment_data = ""
    if include_enrichment:
        enrichment_data = enrich_ioc(threat_input)
    
    # Build context with enrichment
    if enrichment_data and enrichment_data != "No network enrichment available.":
        full_input_context = f"{threat_input}\n\n[NETWORK INTELLIGENCE]:\n{enrichment_data}"
    else:
        full_input_context = threat_input
    
    # Generate prompts
    summary_prompt = format_template(full_input_context, TEMPLATE_PATH)
    severity_prompt = format_template(full_input_context, SEVERITY_TEMPLATE_PATH)

    # Query LLM
    summary = query_ollama(model, summary_prompt)
    severity_raw = query_ollama(model, severity_prompt)
    severity = parse_severity(severity_raw)
    
    # Extract additional insights
    mitre_tactics = extract_mitre_tactics(summary)
    recommendations = extract_recommendations(summary)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "input": threat_input,
        "summary": summary,
        "severity": str(severity),
        "enrichment": enrichment_data,
        "mitre_tactics": mitre_tactics if mitre_tactics else None,
        "recommendations": recommendations if recommendations else None,
    }


def batch_summarize(
    iocs: List[str],
    model: str = "qwen2.5:7b"
) -> List[ThreatSummaryResult]:
    """
    Summarize multiple IOCs in batch.
    
    Args:
        iocs: List of IOCs to analyze.
        model: The Ollama model to use.
        
    Returns:
        List of ThreatSummaryResult objects.
    """
    results = []
    for ioc in iocs:
        try:
            result = summarize_threat(ioc, model)
            results.append(result)
        except Exception as e:
            print(f"[⚠️ Failed to summarize {ioc}] {e}")
    return results
