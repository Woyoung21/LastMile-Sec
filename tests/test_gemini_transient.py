"""Unit tests for src/common/gemini_transient.py"""

from __future__ import annotations

import pytest

from src.common.gemini_transient import (
    invoke_with_transient_retry,
    is_ratelimit_gemini_error,
    is_transient_gemini_error,
    parse_gemini_fallback_models,
)


def test_is_transient_string_503_429():
    assert is_transient_gemini_error(RuntimeError("503 UNAVAILABLE. high demand"))
    assert is_transient_gemini_error(Exception("429 Too Many Requests"))
    assert is_transient_gemini_error(
        Exception("Service Unavailable: The model is overloaded")
    )
    assert is_transient_gemini_error(Exception("RESOURCE_EXHAUSTED: quota"))


def test_is_not_transient_401_403_400():
    assert not is_transient_gemini_error(Exception("401 Unauthorized"))
    assert not is_transient_gemini_error(Exception("403 Forbidden: invalid key"))
    assert not is_transient_gemini_error(Exception("400 Bad request"))


def test_ratelimit_vs_overload_string():
    assert is_ratelimit_gemini_error(Exception("429 Too Many Requests"))
    assert is_ratelimit_gemini_error(Exception("RESOURCE_EXHAUSTED: quota"))


def test_parse_fallback_models_empty(monkeypatch):
    monkeypatch.delenv("GEMINI_FALLBACK_MODELS", raising=False)
    assert parse_gemini_fallback_models() == []


def test_parse_fallback_models_parsed(monkeypatch):
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", " gemini-2.0-flash, gemini-1.5-flash  ")
    assert parse_gemini_fallback_models() == ["gemini-2.0-flash", "gemini-1.5-flash"]


def test_invoke_per_model_tries_next_after_exhausting(monkeypatch):
    calls: list[str] = []
    monkeypatch.setenv("GEMINI_MAX_ATTEMPTS", "1")
    monkeypatch.setattr("src.common.gemini_transient.random.uniform", lambda a, b: 0.01)

    def per(mid: str) -> str:
        calls.append(mid)
        if mid == "A":
            raise RuntimeError("503 UNAVAILABLE")
        return "ok"

    out = invoke_with_transient_retry(
        per_model=per,
        models=["A", "B"],
        allow_fallback=True,
    )
    assert out == "ok"
    assert calls == ["A", "B"]


def test_429_uses_long_sleep(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setenv("GEMINI_429_DELAY", "60")
    monkeypatch.setenv("GEMINI_MAX_ATTEMPTS", "2")
    monkeypatch.setattr(
        "src.common.gemini_transient.random.uniform",
        lambda a, b: 0.5,
    )
    n = 0

    def flaky():
        nonlocal n
        n += 1
        if n == 1:
            raise Exception("429 Too Many Requests")
        return "x"

    r = invoke_with_transient_retry(flaky, sleep_fn=lambda s: sleeps.append(s))
    assert r == "x"
    assert len(sleeps) == 1
    assert 60.0 <= sleeps[0] <= 62.0
