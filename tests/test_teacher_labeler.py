"""Tests for the multi-provider TeacherLabeler."""
from unittest.mock import MagicMock, patch

import pytest

from threat_intel_aggregator.evaluation.dataset_builder.labeler import (
    TeacherLabeler,
    detect_provider,
)

IOC_JSON = '[{"value": "evil.com", "type": "domain"}, {"value": "1.2.3.4", "type": "ip"}]'


def _resp(payload):
    """A fake requests.Response with the given .json() payload."""
    r = MagicMock()
    r.status_code = 200
    r.headers = {}
    r.json.return_value = payload
    r.raise_for_status.return_value = None
    return r


# ── provider detection ──────────────────────────────────────────

@pytest.mark.parametrize("model,provider", [
    ("gpt-5.5", "openai"),
    ("gpt-5.5-mini", "openai"),
    ("o3-mini", "openai"),
    ("claude-sonnet-4-6", "anthropic"),
    ("claude-3-5-haiku", "anthropic"),
    ("qwen2.5:7b", "ollama"),
    ("llama3.1:8b", "ollama"),
])
def test_detect_provider(model, provider):
    assert detect_provider(model) == provider


def test_frontier_model_is_not_downgraded():
    """The old bug: a gpt-* model was silently rewritten to qwen2.5:7b."""
    labeler = TeacherLabeler(model="gpt-5.5")
    assert labeler.model == "gpt-5.5"
    assert labeler.provider == "openai"


# ── context budget ──────────────────────────────────────────────

def test_cloud_teacher_uses_larger_context_budget():
    assert TeacherLabeler("gpt-5.5")._max_chars() > TeacherLabeler("qwen2.5:7b")._max_chars()


# ── provider calls (mocked HTTP) ─────────────────────────────────

def test_openai_labeling(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    payload = {"choices": [{"message": {"content": IOC_JSON}}]}
    with patch("threat_intel_aggregator.feed_collection.llm_providers.requests.post",
               return_value=_resp(payload)) as post:
        sample = TeacherLabeler("gpt-5.5").label_text("evil.com hit 1.2.3.4", "s1")
    assert {e.value for e in sample.expected_iocs} == {"evil.com", "1.2.3.4"}
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer sk-test"


def test_anthropic_labeling(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    payload = {"content": [{"text": IOC_JSON}]}
    with patch("threat_intel_aggregator.feed_collection.llm_providers.requests.post",
               return_value=_resp(payload)) as post:
        sample = TeacherLabeler("claude-sonnet-4-6").label_text("evil.com", "s1")
    assert len(sample.expected_iocs) == 2
    assert post.call_args.kwargs["headers"]["x-api-key"] == "sk-ant-test"


def test_ollama_labeling():
    payload = {"response": IOC_JSON}
    with patch("threat_intel_aggregator.evaluation.dataset_builder.labeler.requests.post",
               return_value=_resp(payload)):
        sample = TeacherLabeler("qwen2.5:7b").label_text("evil.com", "s1")
    assert len(sample.expected_iocs) == 2


# ── error handling ──────────────────────────────────────────────

def test_missing_api_key_yields_empty_sample(monkeypatch):
    """A missing key must not abort the batch — the sample comes back empty."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    sample = TeacherLabeler("gpt-5.5").label_text("evil.com", "s1")
    assert sample.expected_iocs == []
    assert sample.id == "s1"


def test_unparseable_response_yields_empty_sample(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    payload = {"choices": [{"message": {"content": "sorry, no IOCs here"}}]}
    with patch("threat_intel_aggregator.feed_collection.llm_providers.requests.post",
               return_value=_resp(payload)):
        sample = TeacherLabeler("gpt-5.5").label_text("benign text", "s1")
    assert sample.expected_iocs == []
