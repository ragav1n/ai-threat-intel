"""
Teacher LLM Labeler for semi-automated dataset creation.

Uses a high-power "teacher" LLM to identify and label IOCs in raw threat
report text, formatting them into the GroundTruthSample expected format.

Three providers are supported, auto-detected from the model name:

  * OpenAI    — gpt-*, o1/o3/o4-*        (key: OPENAI_API_KEY)
  * Anthropic — claude-*                 (key: ANTHROPIC_API_KEY)
  * Ollama    — everything else (local)  (no key required)

A frontier teacher (GPT-4o / Claude) is strongly preferred over a local small
model. Silver labels from a 7B model are a known credibility risk for an
evaluation that itself studies small models — a reviewer reads it as circular.
The previous implementation silently rewrote any requested ``gpt*`` model to
``qwen2.5:7b``, so no frontier teacher was ever actually used; this module
fixes that.
"""

import json
import logging
import os
import re
from typing import List, Optional

import requests

from threat_intel_aggregator.evaluation.ground_truth import ExpectedIOC, GroundTruthSample
from threat_intel_aggregator.feed_collection.llm_ioc_verifier import (
    OLLAMA_URL,
    sanitize_for_prompt,
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

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


def detect_provider(model: str) -> str:
    """Infer the API provider from a model name."""
    m = model.lower()
    if m.startswith(("gpt-", "gpt4", "chatgpt", "o1", "o1-", "o3", "o3-", "o4", "o4-")):
        return "openai"
    if m.startswith("claude"):
        return "anthropic"
    return "ollama"


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

    @staticmethod
    def _api_key(env_var: str, provider: str) -> str:
        key = os.environ.get(env_var)
        if not key:
            raise RuntimeError(
                f"{env_var} is not set — required for the '{provider}' teacher. "
                f"Export it, or pass a local Ollama model instead."
            )
        return key

    def _call_openai(self, prompt: str) -> str:
        # `temperature` is intentionally omitted: GPT-5-series models reject any
        # non-default value (400 unsupported_value). The extraction prompt is
        # tightly structured, so the default sampling is fine for labeling.
        resp = requests.post(
            self.api_url or OPENAI_URL,
            headers={"Authorization": f"Bearer {self._api_key('OPENAI_API_KEY', 'openai')}"},
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    def _call_anthropic(self, prompt: str) -> str:
        resp = requests.post(
            self.api_url or ANTHROPIC_URL,
            headers={
                "x-api-key": self._api_key("ANTHROPIC_API_KEY", "anthropic"),
                "anthropic-version": ANTHROPIC_VERSION,
            },
            json={
                "model": self.model,
                "max_tokens": 4096,
                "temperature": 0.0,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"].strip()

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
        return {
            "openai": self._call_openai,
            "anthropic": self._call_anthropic,
            "ollama": self._call_ollama,
        }[self.provider](prompt)

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
