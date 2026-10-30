"""Ollama failure handling. httpx is faked, so these run without Ollama."""
from types import SimpleNamespace

import httpx
import pytest

from app.ai import ollama_service
from app.config import get_settings

FINDING = SimpleNamespace(title="SQL injection via string-built query", cwe="CWE-89", file_path="app.py",
                          line_start=68, line_end=69, explanation="f-string SQL",
                          code_snippet='sql = f"SELECT * FROM t WHERE x = \'{term}\'"')


class FakeResponse:
    def __init__(self, status=200, body=None, raw=None):
        self.status_code, self._body, self._raw = status, body, raw

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=httpx.Request("POST", "http://x"),
                                        response=httpx.Response(self.status_code))

    def json(self):
        if self._raw is not None:
            raise ValueError("not json")
        return self._body


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "OLLAMA_MODEL", "gemma4:e2b")
    monkeypatch.setattr(httpx, "get", lambda *a, **k: FakeResponse(body={"models": [{"name": "gemma4:e2b"}]}))
    return monkeypatch


def _post(*responses):
    calls = []

    def fake(url, json, timeout):
        calls.append(json)
        r = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(r, Exception):
            raise r
        return r

    return fake, calls


def test_success_sends_think_false_and_returns_advisory_text(configured):
    fake, calls = _post(FakeResponse(body={"response": "  What is wrong: ...  "}))
    configured.setattr(httpx, "post", fake)
    out = ollama_service.explain_finding(FINDING)
    assert out["available"] is True and out["text"] == "What is wrong: ..."
    assert "advisory" in out["advisory"].lower()
    assert calls[0]["think"] is False


def test_retries_without_think_when_model_rejects_it(configured):
    fake, calls = _post(FakeResponse(status=400), FakeResponse(body={"response": "ok"}))
    configured.setattr(httpx, "post", fake)
    assert ollama_service.explain_finding(FINDING)["text"] == "ok"
    assert "think" not in calls[1]


@pytest.mark.parametrize("response, message", [
    (httpx.ReadTimeout("slow"), "did not answer within"),
    (httpx.ConnectError("refused"), "request failed"),
    (FakeResponse(status=500), "request failed"),
    (FakeResponse(raw=b"<html>"), "request failed"),
    (FakeResponse(body=["not", "an", "object"]), "empty or malformed"),
    (FakeResponse(body={"response": "   "}), "empty or malformed"),
    (FakeResponse(body={"response": 42}), "empty or malformed"),
])
def test_failures_never_raise_and_never_fake_text(configured, response, message):
    fake, _ = _post(response)
    configured.setattr(httpx, "post", fake)
    out = ollama_service.explain_finding(FINDING)
    assert out["available"] is False and out["text"] is None and message in out["message"]


def test_long_output_is_capped(configured):
    fake, _ = _post(FakeResponse(body={"response": "x" * 10_000}))
    configured.setattr(httpx, "post", fake)
    assert len(ollama_service.explain_finding(FINDING)["text"]) == ollama_service.MAX_CHARS


def test_missing_model_skips_generation(monkeypatch):
    monkeypatch.setattr(get_settings(), "OLLAMA_MODEL", "not-pulled:7b")
    monkeypatch.setattr(httpx, "get", lambda *a, **k: FakeResponse(body={"models": [{"name": "gemma4:e2b"}]}))
    monkeypatch.setattr(httpx, "post", lambda *a, **k: pytest.fail("must not call generate"))
    out = ollama_service.explain_finding(FINDING)
    assert out["available"] is False and "ollama pull not-pulled:7b" in out["message"]


def test_unreachable_server(monkeypatch):
    def refuse(*a, **k):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(httpx, "get", refuse)
    status = ollama_service.status()
    assert status["available"] is False and "works fully without it" in status["message"]


def test_latest_tag_matches_bare_name(monkeypatch):
    assert ollama_service._model_matches("llama3.2", ["llama3.2:latest"])
    assert not ollama_service._model_matches("gemma4:e2b", ["gemma4:e4b"])
