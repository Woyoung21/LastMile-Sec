"""Thin re-export of unified Gemini transient retry (Section 4 call sites)."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from src.common.gemini_transient import (
    invoke_with_transient_retry as _invoke_core,
    is_transient_gemini_error,
)
from src.section4_remediation import config

# Structured output + tools: do not add env-driven model fallbacks in this path.
# Default allow_fallback in core applies only to per_model=...; this wrapper uses fn= only.

T = TypeVar("T")

__all__ = ["invoke_with_transient_retry", "is_transient_gemini_error"]


def invoke_with_transient_retry(fn: Callable[[], T]) -> T:
    """Run ``fn``; on transient 429/503, full-jitter / 429 long sleep (see src/common/gemini_transient)."""
    return _invoke_core(
        fn,
        max_attempts=config.GEMINI_TRANSIENT_MAX_ATTEMPTS,
        base_delay=config.GEMINI_TRANSIENT_BASE_DELAY_SEC,
        max_delay=config.GEMINI_MAX_DELAY,
        rate_limit_delay=config.GEMINI_429_DELAY,
    )
