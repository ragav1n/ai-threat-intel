"""
LLM-based IOC Verification Module.

Provides a second-pass verification of regex-extracted IOCs using a local
Ollama LLM. The LLM evaluates whether each IOC is a genuine threat indicator
and assigns a confidence score.

This is combined with the regex confidence via the confidence_fusion module
to produce a final fused score.

Novelty: UTwente (2025) uses LLM to generate regex. LANCE uses cloud APIs.
This module uses a local LLM for verification with multi-factor confidence fusion.
"""
import json
import re
import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type

logger = logging.getLogger(__name__)

# Configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "60"))  # Shorter timeout for verification
DEFAULT_MODEL = os.getenv("IOC_VERIFIER_MODEL", "qwen2.5:7b")

# Allowed IOC types for validation
ALLOWED_IOC_TYPES = {
    "ip", "ipv6", "domain", "url", "md5", "sha1", "sha256",
    "cve", "email", "registry_key", "file_path", "unknown", "auto",
}

# Maximum length for LLM reasoning returned to user (prevent info leakage)
MAX_REASONING_LENGTH = 300


def sanitize_for_prompt(text: str, max_length: int = 500) -> str:
    """
    Sanitize user-supplied text before inserting into an LLM prompt.
    
    Guards against prompt injection by:
    - Truncating to max_length
    - Stripping curly braces (prevents format string attacks)
    - Removing common injection patterns (SYSTEM, IGNORE, etc.)
    - Removing backtick/code block markers
    - Collapsing excessive whitespace
    """
    if not text:
        return ""
    
    text = text[:max_length]
    
    # Strip format-string-dangerous characters
    text = text.replace("{", "").replace("}", "")
    
    # Remove common prompt injection patterns
    injection_patterns = [
        r'(?i)\b(SYSTEM|IGNORE\s+PREVIOUS|FORGET\s+EVERYTHING|DISREGARD)\b',
        r'(?i)\b(NEW\s+INSTRUCTIONS?|OVERRIDE|ACT\s+AS|YOU\s+ARE\s+NOW)\b',
        r'```',           # Code block markers
        r'<[^>]+>',       # HTML/XML-like tags
    ]
    for pattern in injection_patterns:
        text = re.sub(pattern, '[FILTERED]', text)
    
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text


def truncate_reasoning(reasoning: str) -> str:
    """Truncate LLM reasoning to prevent information leakage."""
    if len(reasoning) > MAX_REASONING_LENGTH:
        return reasoning[:MAX_REASONING_LENGTH] + "..."
    return reasoning


# Prompt template for IOC verification
IOC_VERIFY_PROMPT = """You are a cybersecurity threat intelligence analyst. Analyze the following potential Indicator of Compromise (IOC) and determine if it is a genuine threat indicator.

IOC Value: {ioc_value}
IOC Type: {ioc_type}
Context: {context}

Respond ONLY with a JSON object (no markdown, no extra text):
{{
    "is_valid_ioc": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}}

Guidelines:
- is_valid_ioc: true if this appears to be a genuine threat indicator, false if benign/false positive
- confidence: your confidence in the assessment (0.0 = no confidence, 1.0 = certain)
- For IPs: consider if it's a known legitimate service (DNS, CDN) vs. suspicious
- For domains: consider DGA patterns, suspicious TLDs, known malicious patterns
- For hashes: consider if it matches known malware hash patterns
- For URLs: consider suspicious paths, payloads, phishing patterns
- For CVEs: these are almost always valid threat indicators
"""


@dataclass
class LLMVerification:
    """Result of LLM verification for a single IOC."""
    is_valid_ioc: bool
    llm_confidence: float
    reasoning: str
    model_used: str = ""
    error: Optional[str] = None
    
    @staticmethod
    def error_result(error_msg: str) -> "LLMVerification":
        """Create an error result when verification fails."""
        return LLMVerification(
            is_valid_ioc=True,  # Default to valid on error (conservative)
            llm_confidence=0.5,  # Neutral confidence
            reasoning=f"LLM verification failed: {error_msg}",
            error=error_msg,
        )


@dataclass
class VerifiedIOC:
    """An IOC that has been verified by both regex and LLM."""
    value: str
    ioc_type: str
    regex_confidence: float
    llm_confidence: float
    fused_confidence: float
    is_valid_ioc: bool
    llm_reasoning: str
    llm_verified: bool
    context_snippet: str = ""
    deobfuscated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MongoDB storage."""
        return {
            "ioc": self.value,
            "type": self.ioc_type,
            "regex_confidence": round(self.regex_confidence, 4),
            "llm_confidence": round(self.llm_confidence, 4),
            "fused_confidence": round(self.fused_confidence, 4),
            "is_valid_ioc": self.is_valid_ioc,
            "llm_reasoning": self.llm_reasoning,
            "llm_verified": self.llm_verified,
            "deobfuscated": self.deobfuscated,
        }


class LLMIOCVerifier:
    """
    Verifies IOCs using a local Ollama LLM.
    
    Sends each IOC with its context to the LLM for verification,
    producing a confidence score and validity assessment.
    """
    
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        ollama_url: str = OLLAMA_URL,
        timeout: int = OLLAMA_TIMEOUT,
        max_workers: int = 2,
    ):
        self.model = model
        self.ollama_url = ollama_url
        self.timeout = timeout
        self.max_workers = max_workers
        self._available: Optional[bool] = None
    
    def is_available(self) -> bool:
        """Check if Ollama is running and the model is available."""
        if self._available is not None:
            return self._available
            
        try:
            response = requests.get(
                f"{self.ollama_url}/api/tags", timeout=5
            )
            if response.status_code == 200:
                models = [m["name"] for m in response.json().get("models", [])]
                self._available = any(self.model in m for m in models)
            else:
                self._available = False
        except Exception:
            self._available = False
        
        if not self._available:
            logger.warning(f"⚠️ LLM IOC Verifier unavailable (model={self.model})")
        
        return self._available
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_fixed(2),
        retry=retry_if_exception_type(requests.RequestException),
    )
    def _query_ollama(self, prompt: str) -> str:
        """Send a prompt to Ollama and return the response."""
        response = requests.post(
            f"{self.ollama_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,  # Low temperature for consistent verification
                    "num_predict": 200,  # Short responses expected
                },
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()["response"].strip()
    
    def _parse_llm_response(self, raw_response: str) -> LLMVerification:
        """Parse the LLM JSON response into a structured result."""
        try:
            # Try to extract JSON from the response
            # Handle cases where LLM wraps in markdown code blocks
            json_match = re.search(r'\{[^{}]*\}', raw_response, re.DOTALL)
            if not json_match:
                return LLMVerification.error_result("No JSON found in LLM response")
            
            data = json.loads(json_match.group())
            
            is_valid = bool(data.get("is_valid_ioc", True))
            confidence = float(data.get("confidence", 0.5))
            reasoning = str(data.get("reasoning", "No reasoning provided"))
            
            # Clamp confidence
            confidence = max(0.0, min(1.0, confidence))
            
            return LLMVerification(
                is_valid_ioc=is_valid,
                llm_confidence=confidence,
                reasoning=reasoning,
                model_used=self.model,
            )
            
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return LLMVerification.error_result(f"Parse error: {e}")
    
    def verify_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        context_snippet: str = "",
    ) -> LLMVerification:
        """
        Verify a single IOC using the LLM.
        
        Args:
            ioc_value: The IOC value (IP, domain, hash, etc.).
            ioc_type: Type of IOC (ip, domain, url, md5, sha256, etc.).
            context_snippet: Surrounding text context for better analysis.
            
        Returns:
            LLMVerification result with confidence and validity.
        """
        if not self.is_available():
            return LLMVerification.error_result("Ollama not available")
        
        # Sanitize inputs before prompt injection
        safe_ioc = sanitize_for_prompt(ioc_value, max_length=500)
        safe_type = ioc_type if ioc_type in ALLOWED_IOC_TYPES else "unknown"
        safe_context = sanitize_for_prompt(
            context_snippet[:200] if context_snippet else "No context available",
            max_length=200,
        )
        
        prompt = IOC_VERIFY_PROMPT.format(
            ioc_value=safe_ioc,
            ioc_type=safe_type,
            context=safe_context,
        )
        
        try:
            raw_response = self._query_ollama(prompt)
            result = self._parse_llm_response(raw_response)
            result.model_used = self.model
            result.reasoning = truncate_reasoning(result.reasoning)
            
            logger.info(
                f"🤖 LLM verified {safe_type}:{safe_ioc[:30]}... → "
                f"valid={result.is_valid_ioc}, confidence={result.llm_confidence:.2f}"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"LLM verification error for {ioc_value}: {e}")
            return LLMVerification.error_result(str(e))
    
    def batch_verify(
        self,
        ioc_matches: List[Any],
        max_iocs: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Verify multiple IOCs in batch.
        
        Args:
            ioc_matches: List of IOCMatch objects from regex extraction.
            max_iocs: Maximum number of IOCs to verify (LLM calls are slow).
            
        Returns:
            List of dicts with original IOC data + LLM verification results.
        """
        if not self.is_available():
            logger.warning("⚠️ LLM not available, skipping batch verification")
            return [
                {
                    "ioc": m.value,
                    "type": str(m.ioc_type),
                    "regex_confidence": m.confidence,
                    "llm_confidence": None,
                    "llm_verified": False,
                    "is_valid_ioc": True,
                    "llm_reasoning": "LLM unavailable",
                    "context_snippet": getattr(m, 'context_snippet', ''),
                }
                for m in ioc_matches
            ]
        
        # Limit to top IOCs by confidence (most impactful to verify)
        to_verify = sorted(ioc_matches, key=lambda m: m.confidence, reverse=True)[:max_iocs]
        results = []
        
        logger.info(f"🤖 Starting LLM verification of {len(to_verify)} IOCs...")
        
        for i, match in enumerate(to_verify):
            verification = self.verify_ioc(
                ioc_value=match.value,
                ioc_type=str(match.ioc_type),
                context_snippet=getattr(match, 'context_snippet', ''),
            )
            
            results.append({
                "ioc": match.value,
                "type": str(match.ioc_type),
                "regex_confidence": match.confidence,
                "llm_confidence": verification.llm_confidence,
                "llm_verified": verification.error is None,
                "is_valid_ioc": verification.is_valid_ioc,
                "llm_reasoning": verification.reasoning,
                "context_snippet": getattr(match, 'context_snippet', ''),
            })
            
            if (i + 1) % 10 == 0:
                logger.info(f"  Verified {i + 1}/{len(to_verify)} IOCs")
        
        # Add unverified IOCs (beyond max_iocs limit)
        verified_values = {r["ioc"] for r in results}
        for match in ioc_matches:
            if match.value not in verified_values:
                results.append({
                    "ioc": match.value,
                    "type": str(match.ioc_type),
                    "regex_confidence": match.confidence,
                    "llm_confidence": None,
                    "llm_verified": False,
                    "is_valid_ioc": True,
                    "llm_reasoning": "Not verified (batch limit exceeded)",
                    "context_snippet": getattr(match, 'context_snippet', ''),
                })
        
        logger.info(f"✅ LLM verification complete: {len(to_verify)} verified, {len(ioc_matches) - len(to_verify)} skipped")
        
        return results


# Singleton verifier instance
_verifier_instance: Optional[LLMIOCVerifier] = None


def get_llm_verifier(model: str = DEFAULT_MODEL) -> LLMIOCVerifier:
    """Get or create the singleton LLM IOC verifier."""
    global _verifier_instance
    if _verifier_instance is None or _verifier_instance.model != model:
        _verifier_instance = LLMIOCVerifier(model=model)
    return _verifier_instance
