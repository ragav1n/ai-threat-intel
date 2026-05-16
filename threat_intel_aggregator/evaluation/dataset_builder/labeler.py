"""
Teacher LLM Labeler for semi-automated dataset creation.

Uses a high-power "teacher" LLM to identify and label IOCs in raw threat
report text, formatting them into the GroundTruthSample expected format.

Providers (OpenAI / Anthropic / Gemini / Ollama) are auto-detected from the
model name; see `feed_collection.llm_providers`, the shared client module.

A frontier teacher (GPT-5.5 / Claude / Gemini) is strongly preferred over a
local small model. Silver labels from a 7B model are a known credibility risk
for an evaluation that itself studies small models — a reviewer reads it as
circular. The previous implementation silently rewrote any requested ``gpt*``
model to ``qwen2.5:7b``, so no frontier teacher was ever actually used; this
module fixes that.
"""

import json
import logging
import re
from typing import List, Optional

import requests

from threat_intel_aggregator.evaluation.ground_truth import ExpectedIOC, GroundTruthSample
from threat_intel_aggregator.feed_collection.llm_ioc_verifier import (
    OLLAMA_URL,
    sanitize_for_prompt,
)
from threat_intel_aggregator.feed_collection.llm_providers import (
    call_cloud, detect_provider,
)

logger = logging.getLogger(__name__)

TEACHER_PROMPT = """Act as a expert Cyber Threat Intelligence (CTI) analyst.
I will provide a raw threat report. Your task is to extract all Indicators of Compromise (IOCs) mentioned in the text.

IOC Types to find:
- ip (IPv4 and IPv6)
- domain
- url
- md5, sha1, sha256 (hashes)
- email
- cve

Guidelines:
1. ONLY extract items described as malicious, suspicious, or involved in the threat activity.
2. If an IOC is defanged (e.g., hxxp://, [.]), REFANG it (e.g., http://, .).
3. Do NOT extract benign items like company websites, documentation links, or common tools unless they are specifically part of the threat.
4. If the same IOC appears multiple times, only list it once.

Respond ONLY with a JSON array of objects, one for each IOC found. Format:
[
    {{"value": "1.2.3.4", "type": "ip"}},
    {{"value": "evil.com", "type": "domain"}},
    ...
]

Report Text:
{text}
"""

class TeacherLabeler:
    """Semi-automated labeling using a 'Teacher' LLM."""

    # Context budget. A frontier model has a ~1M-token window and must ingest
    # the WHOLE report — CTI reports often park their IOC table in a long
    # appendix, so any low cap silently drops real labels. 500k chars (~125k
    # tokens) covers any realistic report well within the model's window. A
    # local small model is still truncated so it does not choke.
    CLOUD_MAX_CHARS = 500000
    OLLAMA_MAX_CHARS = 2000

    def __init__(self, model: str = "gpt-5.5", api_url: Optional[str] = None):
        """
        Args:
            model:   teacher model name; the provider is auto-detected from it.
            api_url: explicit endpoint override (mainly for tests / proxies).
                     When None, the provider's default endpoint is used.
        """
        self.model = model
        self.provider = detect_provider(model)
        self.api_url = api_url
        if self.provider == "ollama":
            logger.warning(
                "Teacher model '%s' resolves to a LOCAL Ollama model. Prefer a "
                "frontier teacher (gpt-4o / claude-*) for publication-grade labels.",
                model,
            )

    # ── provider calls ──────────────────────────────────────────

    def _max_chars(self) -> int:
        return self.OLLAMA_MAX_CHARS if self.provider == "ollama" else self.CLOUD_MAX_CHARS

    def _call_ollama(self, prompt: str) -> str:
        resp = requests.post(
            f"{self.api_url or OLLAMA_URL}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.0},
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["response"].strip()

    def _call_llm(self, prompt: str) -> str:
        if self.provider == "ollama":
            return self._call_ollama(prompt)
        # A teacher report can yield a long IOC list — allow generous output.
        return call_cloud(self.model, prompt, max_tokens=8192, timeout=120)

    # ── labeling ────────────────────────────────────────────────

    def label_text(self, text: str, sample_id: str, category: str = "true_positive",
                   tags: List[str] = None) -> GroundTruthSample:
        """Call the teacher LLM to extract labels and return a GroundTruthSample.

        On any failure (network, auth, unparseable response) an empty-label
        sample is returned and the error logged, so a batch build does not abort.
        """
        logger.info("Labeling sample %s with %s teacher '%s'...",
                    sample_id, self.provider, self.model)

        safe_text = sanitize_for_prompt(text, max_length=self._max_chars())
        prompt = TEACHER_PROMPT.format(text=safe_text)

        try:
            raw_response = self._call_llm(prompt)

            json_match = re.search(r'\[.*\]', raw_response, re.DOTALL)
            if not json_match:
                logger.error("No JSON array found in teacher response for %s", sample_id)
                return GroundTruthSample(id=sample_id, text=text, expected_iocs=[],
                                         category=category, tags=tags or [])

            ioc_data = json.loads(json_match.group())
            expected_iocs = [
                ExpectedIOC(item["value"], item["type"])
                for item in ioc_data
                if isinstance(item, dict) and item.get("value") and item.get("type")
            ]

            return GroundTruthSample(
                id=sample_id,
                text=text,
                expected_iocs=expected_iocs,
                category=category,
                tags=tags or [],
            )

        except Exception as e:
            logger.error("Failed to label sample %s: %s", sample_id, e)
            return GroundTruthSample(id=sample_id, text=text, expected_iocs=[],
                                     category=category, tags=tags or [])
