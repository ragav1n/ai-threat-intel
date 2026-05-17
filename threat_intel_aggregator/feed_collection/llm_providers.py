"""
Shared multi-provider LLM client helpers.

One place for provider detection and the cloud-API call format of each frontier
vendor, used by both the IOC verifier (`LLMIOCVerifier`) and the dataset
teacher labeler (`TeacherLabeler`). Local Ollama calls stay in each caller —
their payloads differ (the verifier wants short, low-temperature responses; the
labeler wants long ones) — so only provider detection and the cloud calls,
where the real duplication lives, are shared here.

Providers are auto-detected from the model name:
  openai     gpt-*, o1/o3/o4-*      key: OPENAI_API_KEY
  anthropic  claude-*               key: ANTHROPIC_API_KEY
  gemini     gemini-*               key: GEMINI_API_KEY (or GOOGLE_API_KEY)
  ollama     everything else (local, no key)
"""
import os
import time

import requests

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
GEMINI_URL = ("https://generativelanguage.googleapis.com/v1beta/"
              "models/{model}:generateContent")

# provider -> environment variable(s) that may hold its API key
_PROVIDER_KEYS = {
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
}

CLOUD_PROVIDERS = frozenset(_PROVIDER_KEYS)


def detect_provider(model: str) -> str:
    """Infer the API provider from a model name."""
    m = model.lower()
    if m.startswith(("gpt-", "gpt4", "chatgpt", "o1", "o1-", "o3", "o3-", "o4", "o4-")):
        return "openai"
    if m.startswith("claude"):
        return "anthropic"
    if m.startswith("gemini"):
        return "gemini"
    return "ollama"


def cloud_api_key_present(provider: str) -> bool:
    """True if an API key for the given cloud provider is set in the env."""
    return any(os.environ.get(v) for v in _PROVIDER_KEYS.get(provider, ()))


# HTTP statuses worth retrying: rate limits and transient server errors.
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


def _post_with_retry(url: str, *, headers: dict, json: dict, timeout: int,
                     max_attempts: int = 6) -> requests.Response:
    """POST with exponential backoff on rate-limit and transient server errors.

    Cloud providers rate-limit sustained workloads; without backoff a 429
    aborts the call and the verification silently falls back to regex-only.
    A Retry-After header, when present, overrides the computed delay.
    """
    delay = 4.0
    resp = requests.post(url, headers=headers, json=json, timeout=timeout)
    for _ in range(max_attempts - 1):
        if resp.status_code not in _RETRY_STATUS:
            return resp
        retry_after = resp.headers.get("Retry-After", "")
        wait = float(retry_after) if retry_after.isdigit() else delay
        time.sleep(wait)
        delay = min(delay * 2, 60.0)
        resp = requests.post(url, headers=headers, json=json, timeout=timeout)
    return resp


def _api_key(provider: str) -> str:
    for var in _PROVIDER_KEYS.get(provider, ()):
        val = os.environ.get(var)
        if val:
            return val
    expected = " / ".join(_PROVIDER_KEYS.get(provider, ("?",)))
    raise RuntimeError(f"No API key for '{provider}' — set {expected} in the "
                       f"environment (or a .env file).")


def call_openai(model: str, prompt: str, timeout: int = 120) -> str:
    # `temperature` is omitted — GPT-5-series models reject any non-default value.
    resp = _post_with_retry(
        OPENAI_URL,
        headers={"Authorization": f"Bearer {_api_key('openai')}"},
        json={"model": model, "messages": [{"role": "user", "content": prompt}]},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def call_anthropic(model: str, prompt: str, max_tokens: int = 4096,
                   timeout: int = 120) -> str:
    resp = _post_with_retry(
        ANTHROPIC_URL,
        headers={"x-api-key": _api_key("anthropic"),
                 "anthropic-version": ANTHROPIC_VERSION},
        json={"model": model, "max_tokens": max_tokens, "temperature": 0.0,
              "messages": [{"role": "user", "content": prompt}]},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["content"][0]["text"].strip()


def call_gemini(model: str, prompt: str, max_tokens: int = 4096,
                timeout: int = 120) -> str:
    resp = _post_with_retry(
        GEMINI_URL.format(model=model),
        headers={"x-goog-api-key": _api_key("gemini")},
        json={"contents": [{"parts": [{"text": prompt}]}],
              "generationConfig": {"temperature": 0.0,
                                   "maxOutputTokens": max_tokens}},
        timeout=timeout,
    )
    resp.raise_for_status()
    parts = resp.json()["candidates"][0].get("content", {}).get("parts", [])
    # Thinking models (e.g. Gemini 3 Flash) emit thought-only parts next to the
    # answer; keep only the parts that carry visible text.
    return "".join(p["text"] for p in parts if "text" in p).strip()


def call_cloud(model: str, prompt: str, max_tokens: int = 4096,
               timeout: int = 120) -> str:
    """Send one prompt to the model's cloud provider; return the text response.

    Raises ValueError for a local (Ollama) model — those are not cloud-routed.
    """
    provider = detect_provider(model)
    if provider == "openai":
        return call_openai(model, prompt, timeout)
    if provider == "anthropic":
        return call_anthropic(model, prompt, max_tokens, timeout)
    if provider == "gemini":
        return call_gemini(model, prompt, max_tokens, timeout)
    raise ValueError(f"'{model}' is a local model (provider={provider}), "
                     f"not a cloud model — use the Ollama path instead.")
