"""
Agentic TTP Predictor — Multi-step LLM pipeline for threat forecasting.

Uses a 3-step agentic approach:
  1. Classify the current attack stage in the MITRE ATT&CK kill chain
  2. Graph-informed reasoning about the attacker's next logical move
  3. Probabilistic TTP prediction with defensive recommendations
"""
import json
import re
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from .models import CampaignContext, PredictedTTP, TTPPrediction

logger = logging.getLogger(__name__)

# Default LLM settings
DEFAULT_MODEL = "qwen2.5:7b"
OLLAMA_URL = "http://localhost:11434"
OLLAMA_TIMEOUT = 120

# MITRE ATT&CK Kill Chain phases (ordered)
KILL_CHAIN_PHASES = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# ---------- Prompt Templates ----------

STAGE_CLASSIFICATION_PROMPT = """You are a senior threat intelligence analyst. Based on the following campaign profile, classify which MITRE ATT&CK kill chain stage this campaign is CURRENTLY in.

CAMPAIGN PROFILE:
{campaign_profile}

KILL CHAIN STAGES (in order):
1. Reconnaissance
2. Resource Development
3. Initial Access
4. Execution
5. Persistence
6. Privilege Escalation
7. Defense Evasion
8. Credential Access
9. Discovery
10. Lateral Movement
11. Collection
12. Command and Control
13. Exfiltration
14. Impact

Respond with ONLY a JSON object:
{{"current_stage": "<stage name>", "confidence": <0.0-1.0>, "evidence": "<brief evidence>"}}"""


REASONING_PROMPT = """You are a senior threat intelligence analyst performing predictive analysis. Given the current attack stage and campaign context, reason about what the attacker would most likely do NEXT.

CURRENT STAGE: {current_stage}

CAMPAIGN CONTEXT:
{campaign_profile}

MITRE ATT&CK KNOWLEDGE:
{mitre_context}

GRAPH INTELLIGENCE:
{graph_context}

Think step-by-step:
1. What has the attacker accomplished so far based on the IOC evidence?
2. What is the natural progression from the current stage?
3. What specific MITRE ATT&CK techniques would they likely use next?
4. What defensive actions should be prioritized?

Provide your reasoning as a detailed paragraph."""


PREDICTION_PROMPT = """You are a threat prediction engine. Based on the following analysis, output a structured prediction of the top 3 most likely NEXT MITRE ATT&CK techniques the campaign will execute.

ANALYSIS:
{reasoning}

CURRENT STAGE: {current_stage}

Respond with ONLY a JSON object in this exact format:
{{
  "predictions": [
    {{
      "tactic": "<MITRE tactic name>",
      "technique_id": "<e.g. T1021>",
      "technique_name": "<technique name>",
      "confidence": <0.0-1.0>,
      "reasoning": "<one-sentence reasoning>"
    }},
    {{
      "tactic": "<MITRE tactic name>",
      "technique_id": "<e.g. T1059>",
      "technique_name": "<technique name>",
      "confidence": <0.0-1.0>,
      "reasoning": "<one-sentence reasoning>"
    }},
    {{
      "tactic": "<MITRE tactic name>",
      "technique_id": "<e.g. T1071>",
      "technique_name": "<technique name>",
      "confidence": <0.0-1.0>,
      "reasoning": "<one-sentence reasoning>"
    }}
  ],
  "defensive_recommendations": [
    "<recommendation 1>",
    "<recommendation 2>",
    "<recommendation 3>"
  ]
}}"""


class TTPPredictor:
    """
    Agentic TTP prediction using a 3-step LLM pipeline.

    Step 1: Classify current attack stage
    Step 2: Graph-informed reasoning
    Step 3: Probabilistic prediction output
    """

    def __init__(self, model: str = DEFAULT_MODEL, ollama_url: str = OLLAMA_URL, timeout: int = OLLAMA_TIMEOUT):
        self.model = model
        self.ollama_url = ollama_url
        self.timeout = timeout

    def predict(self, context: CampaignContext) -> TTPPrediction:
        """
        Run the full 3-step agentic prediction pipeline.

        Args:
            context: Rich campaign context from GraphContextRetriever.

        Returns:
            TTPPrediction with current stage, predictions, and recommendations.
        """
        logger.info(f"Starting TTP prediction for campaign {context.campaign_id}")

        # Step 1: Classify current attack stage
        current_stage = self._classify_attack_stage(context.campaign_profile)
        logger.info(f"Step 1 — Current stage: {current_stage}")

        # Step 2: Graph-informed reasoning
        mitre_text = self._format_mitre_context(context.mitre_context)
        graph_text = self._format_graph_context(context.graph_neighbors)
        reasoning = self._reason_next_move(
            current_stage, context.campaign_profile, mitre_text, graph_text
        )
        logger.info(f"Step 2 — Reasoning complete ({len(reasoning)} chars)")

        # Step 3: Probabilistic prediction
        predictions, recommendations = self._generate_prediction(reasoning, current_stage)
        logger.info(f"Step 3 — Generated {len(predictions)} predictions")

        return TTPPrediction(
            campaign_id=context.campaign_id,
            campaign_label=context.campaign_label,
            current_stage=current_stage,
            predictions=predictions,
            defensive_recommendations=recommendations,
            model_used=self.model,
        )

    def _query_ollama(self, prompt: str) -> str:
        """Send a prompt to Ollama and return the response."""
        import requests

        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 1024},
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except requests.exceptions.ConnectionError:
            logger.error("Ollama is not running or unreachable")
            raise RuntimeError("Ollama is not available. Start Ollama to enable predictions.")
        except requests.exceptions.Timeout:
            logger.error("Ollama request timed out")
            raise RuntimeError("Ollama request timed out")
        except Exception as e:
            logger.error(f"Ollama query failed: {e}")
            raise RuntimeError(f"LLM query failed: {e}")

    def _classify_attack_stage(self, campaign_profile: str) -> str:
        """
        Step 1: Classify which MITRE ATT&CK kill chain stage the campaign is in.
        Falls back to heuristic classification when LLM is unavailable.
        """
        prompt = STAGE_CLASSIFICATION_PROMPT.format(campaign_profile=campaign_profile)

        try:
            raw = self._query_ollama(prompt)
            parsed = self._extract_json(raw)

            if parsed and "current_stage" in parsed:
                stage = parsed["current_stage"]
                # Validate against known phases
                for phase in KILL_CHAIN_PHASES:
                    if phase.lower() == stage.lower():
                        return phase
                # Fuzzy match
                for phase in KILL_CHAIN_PHASES:
                    if phase.lower() in stage.lower() or stage.lower() in phase.lower():
                        return phase

            logger.warning(f"Could not parse stage from LLM response, defaulting to Reconnaissance")
            return "Reconnaissance"

        except RuntimeError:
            # Heuristic fallback: infer stage from IOC types in the campaign profile
            return self._heuristic_stage_classification(campaign_profile)

    def _heuristic_stage_classification(self, campaign_profile: str) -> str:
        """
        Infer the kill chain stage from IOC type distribution when LLM is unavailable.

        Mapping logic:
        - domain/url heavy → Reconnaissance (recon infrastructure)
        - hash/exe/file heavy → Execution (malware delivery)
        - ip heavy → Command and Control (C2 beacons)
        - email heavy → Initial Access (phishing)
        - cve heavy → Initial Access (exploit-based)
        - mixed/unknown → Discovery (general probing)
        """
        profile_lower = campaign_profile.lower()

        # Count IOC type mentions in the profile
        type_signals = {
            "Reconnaissance": ["domain", "url", "whois"],
            "Initial Access": ["email", "cve", "phishing"],
            "Execution": ["hash", "sha256", "sha1", "md5", "exe", "file_path"],
            "Command and Control": ["ip", "ipv4", "ipv6", "c2"],
            "Collection": ["file_path", "registry"],
            "Exfiltration": ["dns", "tunnel"],
        }

        scores = {}
        for stage, keywords in type_signals.items():
            score = sum(profile_lower.count(kw) for kw in keywords)
            if score > 0:
                scores[stage] = score

        if scores:
            best_stage = max(scores, key=scores.get)
            logger.info(f"Heuristic stage classification: {best_stage} (scores: {scores})")
            return best_stage

        # Check severity for additional signal
        if "critical" in profile_lower:
            return "Impact"
        if "high" in profile_lower:
            return "Lateral Movement"

        return "Reconnaissance"

    def _reason_next_move(
        self,
        current_stage: str,
        campaign_profile: str,
        mitre_context: str,
        graph_context: str,
    ) -> str:
        """
        Step 2: Graph-informed reasoning about the attacker's next logical move.
        """
        prompt = REASONING_PROMPT.format(
            current_stage=current_stage,
            campaign_profile=campaign_profile,
            mitre_context=mitre_context if mitre_context else "No MITRE context available.",
            graph_context=graph_context if graph_context else "No graph intelligence available.",
        )

        try:
            return self._query_ollama(prompt)
        except RuntimeError:
            # Fallback: return a minimal reasoning based on kill chain progression
            idx = next(
                (i for i, p in enumerate(KILL_CHAIN_PHASES) if p == current_stage),
                0,
            )
            next_stage = KILL_CHAIN_PHASES[min(idx + 1, len(KILL_CHAIN_PHASES) - 1)]
            return (
                f"Based on the current stage ({current_stage}), the natural progression "
                f"in the MITRE ATT&CK kill chain leads to {next_stage}. "
                f"The campaign has {len(campaign_profile)} characters of context."
            )

    def _generate_prediction(
        self, reasoning: str, current_stage: str
    ) -> tuple:
        """
        Step 3: Generate structured probabilistic TTP predictions.

        Returns:
            Tuple of (predictions: List[PredictedTTP], recommendations: List[str])
        """
        prompt = PREDICTION_PROMPT.format(reasoning=reasoning, current_stage=current_stage)

        try:
            raw = self._query_ollama(prompt)
            parsed = self._extract_json(raw)

            if parsed and "predictions" in parsed:
                predictions = []
                for p in parsed["predictions"][:3]:
                    try:
                        predictions.append(PredictedTTP(
                            tactic=p.get("tactic", "Unknown"),
                            technique_id=p.get("technique_id", "T0000"),
                            technique_name=p.get("technique_name", "Unknown"),
                            confidence=float(p.get("confidence", 0.5)),
                            reasoning=p.get("reasoning", ""),
                        ))
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Skipping malformed prediction: {e}")

                recommendations = parsed.get("defensive_recommendations", [])
                if isinstance(recommendations, list):
                    recommendations = [str(r) for r in recommendations[:5]]
                else:
                    recommendations = []

                return predictions, recommendations

        except RuntimeError:
            pass

        # Fallback: generate a basic prediction from kill chain progression
        return self._fallback_prediction(current_stage), [
            "Monitor network traffic for anomalous patterns",
            "Review endpoint detection logs",
            "Update threat intelligence feeds",
        ]

    def _fallback_prediction(self, current_stage: str) -> List[PredictedTTP]:
        """Generate a basic prediction when LLM is unavailable."""
        idx = next(
            (i for i, p in enumerate(KILL_CHAIN_PHASES) if p == current_stage),
            0,
        )

        # Predict the next 3 stages in the kill chain
        predictions = []
        for offset in range(1, 4):
            next_idx = min(idx + offset, len(KILL_CHAIN_PHASES) - 1)
            next_stage = KILL_CHAIN_PHASES[next_idx]
            predictions.append(PredictedTTP(
                tactic=next_stage,
                technique_id="T0000",
                technique_name=f"Predicted {next_stage} technique",
                confidence=max(0.3, 0.8 - (offset * 0.2)),
                reasoning=f"Natural kill chain progression from {current_stage}",
            ))

        return predictions

    def _extract_json(self, raw: str) -> Optional[dict]:
        """Extract JSON from LLM response, handling markdown wrappers."""
        # Try direct parse
        try:
            return json.loads(raw.strip())
        except json.JSONDecodeError:
            pass

        # Try to find JSON in markdown code blocks
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', raw, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Try to find JSON object in the text
        brace_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', raw, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        logger.warning("Could not extract JSON from LLM response")
        return None

    def _format_mitre_context(self, mitre_context: List[Dict[str, Any]]) -> str:
        """Format MITRE RAG results for the reasoning prompt."""
        if not mitre_context:
            return ""

        lines = []
        for tech in mitre_context[:5]:
            tid = tech.get("technique_id", tech.get("id", "?"))
            name = tech.get("name", "?")
            tactics = tech.get("tactics", [])
            desc = tech.get("description", "")[:200]
            tactic_str = ", ".join(tactics) if isinstance(tactics, list) else str(tactics)
            lines.append(f"- {tid} {name} (Tactics: {tactic_str}): {desc}")

        return "\n".join(lines)

    def _format_graph_context(self, graph_neighbors: Dict[str, List[str]]) -> str:
        """Format graph neighbor data for the reasoning prompt."""
        if not graph_neighbors:
            return ""

        lines = []
        for ioc, neighbors in list(graph_neighbors.items())[:10]:
            if neighbors:
                lines.append(f"- {ioc} is connected to: {', '.join(neighbors[:5])}")

        return "\n".join(lines) if lines else "No significant graph connections found."
