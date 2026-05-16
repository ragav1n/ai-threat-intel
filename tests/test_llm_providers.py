"""Tests for the shared multi-provider LLM client (llm_providers)."""
from unittest.mock import MagicMock, patch

import pytest

from threat_intel_aggregator.feed_collection import llm_providers as lp

POST = "threat_intel_aggregator.feed_collection.llm_providers.requests.post"


def _resp(payload):
    """A fake requests.Response with the given .json() payload."""
    r = MagicMock()
    r.json.return_value = payload
    r.raise_for_status.return_value = None
    return r


# ── provider detection ──────────────────────────────────────────

@pytest.mark.parametrize("model,provider", [
    ("gpt-5.5", "openai"),
    ("o3-mini", "openai"),
    ("claude-sonnet-4-6", "anthropic"),
    ("gemini-2.5-pro", "gemini"),
    ("gemini-1.5-flash", "gemini"),
    ("qwen2.5:7b", "ollama"),
    ("llama3.1:8b", "ollama"),
])
def test_detect_provider(model, provider):
    assert lp.detect_provider(model) == provider


def test_cloud_api_key_present(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert not lp.cloud_api_key_present("anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    assert lp.cloud_api_key_present("anthropic")


def test_gemini_key_falls_back_to_google(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "g-key")
    assert lp.cloud_api_key_present("gemini")


# ── provider calls (mocked HTTP) ─────────────────────────────────

def test_call_openai(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    payload = {"choices": [{"message": {"content": " hello "}}]}
    with patch(POST, return_value=_resp(payload)) as post:
        out = lp.call_openai("gpt-5.5", "hi")
    assert out == "hello"
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer sk-test"
    # temperature must NOT be sent — GPT-5-series rejects a non-default value.
    assert "temperature" not in post.call_args.kwargs["json"]


def test_call_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    payload = {"content": [{"text": "world"}]}
    with patch(POST, return_value=_resp(payload)) as post:
        out = lp.call_anthropic("claude-sonnet-4-6", "hi")
    assert out == "world"
    assert post.call_args.kwargs["headers"]["x-api-key"] == "sk-ant"


def test_call_gemini(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    payload = {"candidates": [{"content": {"parts": [{"text": "gem"}]}}]}
    with patch(POST, return_value=_resp(payload)) as post:
        out = lp.call_gemini("gemini-2.5-pro", "hi")
    assert out == "gem"
    assert post.call_args.kwargs["headers"]["x-goog-api-key"] == "g-key"


def test_call_cloud_dispatches_by_model(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    payload = {"content": [{"text": "dispatched"}]}
    with patch(POST, return_value=_resp(payload)):
        assert lp.call_cloud("claude-sonnet-4-6", "hi") == "dispatched"


def test_call_cloud_rejects_local_model():
    with pytest.raises(ValueError):
        lp.call_cloud("qwen2.5:7b", "hi")


def test_missing_api_key_raises(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        lp.call_openai("gpt-5.5", "hi")
