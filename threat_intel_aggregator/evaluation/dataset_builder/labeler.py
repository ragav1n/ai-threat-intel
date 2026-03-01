"""
Teacher LLM Labeler for semi-automated dataset creation.

Uses a high-power LLM to identify and label IOCs in raw threat report text,
formatting them into the GroundTruthSample expected format.
"""

import json
import logging
import re
from typing import List, Dict, Any, Optional
import requests
from threat_intel_aggregator.evaluation.ground_truth import ExpectedIOC, GroundTruthSample
from threat_intel_aggregator.feed_collection.llm_ioc_verifier import (
    OLLAMA_URL,
    DEFAULT_MODEL,
    sanitize_for_prompt
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
    
    def __init__(self, model: str = "gpt-4o", api_url: Optional[str] = None):
        """
        Initialize the labeler.
        If api_url is None, it defaults to local Ollama if model looks like an Ollama model,
        otherwise it assumes a placeholder for a cloud API.
        """
        self.model = model
        self.api_url = api_url or OLLAMA_URL
        
    def label_text(self, text: str, sample_id: str, category: str = "true_positive", tags: List[str] = None) -> GroundTruthSample:
        """
        Call the LLM to extract labels and return a GroundTruthSample.
        """
        logger.info(f"Labeling sample {sample_id}...")
        
        safe_text = sanitize_for_prompt(text, max_length=2000)
        prompt = TEACHER_PROMPT.format(text=safe_text)
        
        try:
            # For this implementation, we default to the local Ollama if available
            # If the user wants to use GPT-4o, they would need to provide an API key/wrapper
            response = requests.post(
                f"{self.api_url}/api/generate",
                json={
                    "model": self.model if "gpt" not in self.model else "qwen2.5:7b", # Fallback for local testing
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.0}
                },
                timeout=120
            )
            response.raise_for_status()
            raw_response = response.json()["response"].strip()
            
            # Extract JSON array
            json_match = re.search(r'\[.*\]', raw_response, re.DOTALL)
            if not json_match:
                logger.error(f"No JSON array found in LLM response for {sample_id}")
                return GroundTruthSample(id=sample_id, text=text, expected_iocs=[], category=category, tags=tags or [])
                
            ioc_data = json.loads(json_match.group())
            expected_iocs = [ExpectedIOC(item["value"], item["type"]) for item in ioc_data]
            
            return GroundTruthSample(
                id=sample_id,
                text=text,
                expected_iocs=expected_iocs,
                category=category,
                tags=tags or []
            )
            
        except Exception as e:
            logger.error(f"Failed to label sample {sample_id}: {e}")
            return GroundTruthSample(id=sample_id, text=text, expected_iocs=[], category=category, tags=tags or [])
