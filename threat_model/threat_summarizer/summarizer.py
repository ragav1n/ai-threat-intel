"""
Threat summarization using LLM with Hunter agent enrichment.
Enhanced with MITRE ATT&CK RAG and automated TTP mapping.
"""
import json
import re
import logging
from pathlib import Path
from datetime import datetime
from typing import TypedDict, Optional, List, Dict, Any

from .model_client import query_ollama
from threat_model.hunter import enrich_ioc

# Lazy import for RAG to avoid startup overhead
_mitre_rag = None

logger = logging.getLogger(__name__)

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
TTP_TEMPLATE_PATH = Path(__file__).parent / "ttp_template.txt"


class TTMapping(TypedDict):
    """Type definition for a single TTP mapping."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: Optional[str]


class ThreatSummaryResult(TypedDict):
    """Type definition for threat summary response."""
    timestamp: str
    input: str
    summary: str
    severity: str
    enrichment: str
    mitre_tactics: Optional[List[str]]  # Legacy field for backward compat
    mitre_ttps: Optional[List[TTMapping]]  # New enhanced TTP field
    rag_context: Optional[List[str]]  # Retrieved MITRE context
    recommendations: Optional[List[str]]


def get_mitre_rag():
    """Lazy load MITRE RAG instance."""
    global _mitre_rag
    if _mitre_rag is None:
        try:
            from .mitre_rag import get_mitre_rag as _get_rag
            _mitre_rag = _get_rag()
        except Exception as e:
            logger.warning(f"Failed to load MITRE RAG: {e}")
            return None
    return _mitre_rag


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


def extract_mitre_tactics_legacy(summary: str) -> List[str]:
    """
    Extract potential MITRE ATT&CK tactics from the summary.
    Legacy keyword matching - kept for backward compatibility.
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


def extract_mitre_ttps(
    threat_input: str,
    summary: str,
    model: str = "qwen2.5:7b",
    rag_context: Optional[List[Dict[str, Any]]] = None
) -> List[TTMapping]:
    """
    Extract MITRE ATT&CK TTPs using LLM with RAG context.
    
    Args:
        threat_input: Original threat indicator/description.
        summary: Generated threat summary.
        model: LLM model to use.
        rag_context: Pre-retrieved MITRE context (optional).
        
    Returns:
        List of TTP mappings with confidence scores.
    """
    # Get RAG context if not provided
    if rag_context is None:
        rag = get_mitre_rag()
        if rag:
            try:
                rag_context = rag.retrieve_context(f"{threat_input} {summary}", top_k=5)
            except Exception as e:
                logger.warning(f"RAG retrieval failed: {e}")
                rag_context = []
    
    if not rag_context:
        # Fall back to legacy extraction
        legacy_tactics = extract_mitre_tactics_legacy(summary)
        return [
            TTMapping(
                technique_id="",
                technique_name="",
                tactic=tactic,
                confidence=0.5,
                evidence="Keyword-based detection"
            )
            for tactic in legacy_tactics
        ]
    
    # Format MITRE context for prompt
    context_lines = []
    for ctx in rag_context:
        context_lines.append(
            f"- {ctx['technique_id']} ({ctx['technique_name']}): "
            f"Tactics: {', '.join(ctx.get('tactics', []))}. {ctx.get('description', '')[:100]}"
        )
    mitre_context = "\n".join(context_lines)
    
    # Load and format TTP template
    try:
        template = load_prompt_template(TTP_TEMPLATE_PATH)
        prompt = template.replace("{{MITRE_CONTEXT}}", mitre_context)
        prompt = prompt.replace("{{INPUT}}", f"{threat_input}\n\nSummary: {summary}")
    except Exception as e:
        logger.warning(f"TTP template loading failed: {e}")
        return []
    
    # Query LLM for TTP mapping
    try:
        response = query_ollama(model, prompt)
        
        # Extract JSON from response
        json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # Try to find raw JSON
            json_match = re.search(r'\{.*"ttps".*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                return []
        
        data = json.loads(json_str)
        ttps = data.get("ttps", [])
        
        # Convert to TTMapping format
        result = []
        for ttp in ttps[:5]:  # Limit to 5
            if ttp.get("confidence", 0) >= 0.5:
                result.append(TTMapping(
                    technique_id=ttp.get("technique_id", ""),
                    technique_name=ttp.get("technique_name", ""),
                    tactic=ttp.get("tactic", ""),
                    confidence=float(ttp.get("confidence", 0.5)),
                    evidence=ttp.get("evidence")
                ))
        
        return result
        
    except Exception as e:
        logger.warning(f"TTP extraction failed: {e}")
        return []


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
    include_enrichment: bool = True,
    use_rag: bool = True
) -> ThreatSummaryResult:
    """
    Summarize a threat indicator using LLM with RAG-enhanced context.
    
    Args:
        threat_input: The IOC or threat description to analyze.
        model: The Ollama model to use for summarization.
        include_enrichment: Whether to include Hunter enrichment.
        use_rag: Whether to use MITRE ATT&CK RAG for context.
    
    Returns:
        ThreatSummaryResult with full analysis including TTPs and RAG context.
    """
    # Hunter Agent Enrichment
    enrichment_data = ""
    if include_enrichment:
        enrichment_data = enrich_ioc(threat_input)
    
    # RAG: Retrieve MITRE ATT&CK context
    rag_context = None
    rag_context_strings = None
    
    if use_rag:
        rag = get_mitre_rag()
        if rag:
            try:
                rag_context = rag.retrieve_context(threat_input, top_k=3)
                if rag_context:
                    rag_context_strings = [
                        f"{ctx['technique_id']}: {ctx['technique_name']}"
                        for ctx in rag_context
                    ]
            except Exception as e:
                logger.warning(f"RAG context retrieval failed: {e}")
    
    # Build context with enrichment and RAG
    full_input_context = threat_input
    
    if enrichment_data and enrichment_data != "No network enrichment available.":
        full_input_context += f"\n\n[NETWORK INTELLIGENCE]:\n{enrichment_data}"
    
    if rag_context:
        rag = get_mitre_rag()
        if rag:
            formatted_context = rag.format_context_for_prompt(rag_context)
            full_input_context += f"\n\n{formatted_context}"
    
    # Generate prompts
    summary_prompt = format_template(full_input_context, TEMPLATE_PATH)
    severity_prompt = format_template(full_input_context, SEVERITY_TEMPLATE_PATH)

    # Query LLM
    summary = query_ollama(model, summary_prompt)
    severity_raw = query_ollama(model, severity_prompt)
    severity = parse_severity(severity_raw)
    
    # Extract TTPs with RAG context
    mitre_ttps = extract_mitre_ttps(threat_input, summary, model, rag_context)
    
    # Legacy tactics field (for backward compatibility)
    mitre_tactics = list(set(
        ttp["tactic"] for ttp in mitre_ttps if ttp.get("tactic")
    )) or extract_mitre_tactics_legacy(summary)
    
    # Extract recommendations
    recommendations = extract_recommendations(summary)

    # IST timezone for consistent timestamps
    from datetime import timezone, timedelta
    IST = timezone(timedelta(hours=5, minutes=30))
    timestamp = datetime.now(IST).isoformat()

    return {
        "timestamp": timestamp,
        "input": threat_input,
        "summary": summary,
        "severity": str(severity),
        "enrichment": enrichment_data,
        "mitre_tactics": mitre_tactics if mitre_tactics else None,
        "mitre_ttps": mitre_ttps if mitre_ttps else None,
        "rag_context": rag_context_strings,
        "recommendations": recommendations if recommendations else None,
    }


def batch_summarize(
    iocs: List[str],
    model: str = "qwen2.5:7b",
    use_rag: bool = True
) -> List[ThreatSummaryResult]:
    """
    Summarize multiple IOCs in batch.
    
    Args:
        iocs: List of IOCs to analyze.
        model: The Ollama model to use.
        use_rag: Whether to use MITRE ATT&CK RAG.
        
    Returns:
        List of ThreatSummaryResult objects.
    """
    # Pre-initialize RAG for batch efficiency
    if use_rag:
        rag = get_mitre_rag()
        if rag:
            try:
                rag.initialize()
            except Exception as e:
                logger.warning(f"RAG initialization failed: {e}")
    
    results = []
    for ioc in iocs:
        try:
            result = summarize_threat(ioc, model, use_rag=use_rag)
            results.append(result)
        except Exception as e:
            print(f"[⚠️ Failed to summarize {ioc}] {e}")
    return results
