"""
Unified transient retry for Gemini (google.genai) and LangChain-wrapped calls.

- Full jitter (non-429): sleep ~ U(0, min(GEMINI_MAX_DELAY, GEMINI_BASE_DELAY * 2**attempt))
- 429 / rate limit: wait GEMINI_429_DELAY + small jitter (avoid hammering the API)
- Optional per-model retry chains for GEMINI_FALLBACK_MODELS (Sections 1–2; off for embeddings)
"""

from __future__ import annotations

import logging
import os
import re
import random
import time
from collections.abc import Callable, Sequence
from typing import TypeVar

from google.genai import errors as genai_errors

logger = logging.getLogger(__name__)

T = TypeVar("T")

_JITTER_429 = 1.0  # seconds; added on top of GEMINI_429_DELAY

_TRANSIENT_CODES = frozenset({429, 503})


def is_transient_gemini_error(exc: BaseException) -> bool:
    """True for recoverable load / quota errors; false for auth and invalid requests."""
    if isinstance(exc, genai_errors.ServerError):
        return getattr(exc, "code", None) in _TRANSIENT_CODES
    if isinstance(exc, genai_errors.ClientError):
        code = getattr(exc, "code", None)
        return code in _TRANSIENT_CODES
    return _is_transient_gemini_error_message(str(exc))


def is_ratelimit_gemini_error(exc: BaseException) -> bool:
    """True if we should use the 429 (long) sleep policy."""
    if not is_transient_gemini_error(exc):
        return False
    if isinstance(exc, genai_errors.ServerError) and getattr(exc, "code", None) == 429:
        return True
    if isinstance(exc, genai_errors.ClientError) and getattr(exc, "code", None) == 429:
        return True
    msg = str(exc)
    if re.search(r"\b429\b", msg):
        return True
    u = msg.upper()
    if "TOO MANY REQUESTS" in u or "RATE_LIMIT_EXCEEDED" in u or "QUOTA" in u and "EXCEEDED" in u:
        return True
    if "RESOURCE_EXHAUSTED" in u:
        return True
    return False


def _is_transient_gemini_error_message(msg: str) -> bool:
    if not msg:
        return False
    if re.search(r"\b401\b", msg) or re.search(r"\b403\b", msg) or re.search(r"\b400\b", msg):
        return False
    if "PERMISSION_DENIED" in msg or "API_KEY_INVALID" in msg or "API key not valid" in msg:
        return False
    u = msg.upper()
    if re.search(r"\b503\b", msg) or re.search(r"\b429\b", msg):
        return True
    if "UNAVAILABLE" in u or "RESOURCE_EXHAUSTED" in u:
        return True
    if "SERVICE UNAVAILABLE" in u:
        return True
    if "HIGH DEMAND" in u or "TRY AGAIN" in u:
        return True
    if "RATE LIMIT" in u or "OVERLOADED" in u or "TOO MANY REQUESTS" in u:
        return True
    return False


def load_retry_defaults_from_env() -> dict[str, float | int]:
    """Read global GEMINI_* retry tuning (see plan)."""
    return {
        "max_attempts": _env_int("GEMINI_MAX_ATTEMPTS", 6),
        "base_delay": _env_float("GEMINI_BASE_DELAY", 3.0),
        "max_delay": _env_float("GEMINI_MAX_DELAY", 60.0),
        "rate_limit_delay": _env_float("GEMINI_429_DELAY", 60.0),
    }


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, str(default)))
    except ValueError:
        return default


def parse_gemini_fallback_models() -> list[str]:
    raw = os.environ.get("GEMINI_FALLBACK_MODELS", "")
    if not raw.strip():
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def _sleep_for_transient(
    exc: BaseException,
    attempt: int,
    *,
    base_delay: float,
    max_delay: float,
    rate_limit_delay: float,
) -> float:
    if is_ratelimit_gemini_error(exc):
        s = max(0.0, rate_limit_delay) + random.uniform(0, _JITTER_429)
    else:
        delay_cap = min(max_delay, base_delay * (2**attempt))
        s = random.uniform(0.0, max(0.0, delay_cap))
    return s


def invoke_with_transient_retry(
    fn: Callable[[], T] | None = None,
    *,
    per_model: Callable[[str], T] | None = None,
    models: Sequence[str] | None = None,
    max_attempts: int | None = None,
    base_delay: float | None = None,
    max_delay: float | None = None,
    rate_limit_delay: float | None = None,
    allow_fallback: bool = True,
    sleep_fn: Callable[[float], None] | None = None,
    on_retry: Callable[[int, str | None, BaseException, float], None] | None = None,
) -> T:
    """Run a Gemini call with full-jitter retry; optional per-model fallback chain.

    - Single closure: pass ``fn=lambda: call()``, leave ``per_model`` unset.
    - Model fallback: pass ``per_model=lambda m: call_with_model(m)`` and ``models=[primary, ...]``.
    - When ``allow_fallback`` is False, only ``models[0]`` is used (embeddings: pass one model id).
    """
    defaults = load_retry_defaults_from_env()
    ma = int(max_attempts if max_attempts is not None else int(defaults["max_attempts"]))
    bd = float(base_delay if base_delay is not None else float(defaults["base_delay"]))
    md = float(max_delay if max_delay is not None else float(defaults["max_delay"]))
    rl = float(
        rate_limit_delay if rate_limit_delay is not None else float(defaults["rate_limit_delay"])
    )
    sleep = sleep_fn or time.sleep
    ma = max(1, ma)

    if per_model is not None:
        if not models:
            raise ValueError("invoke_with_transient_retry: models=... is required with per_model=")
        chain = list(models) if allow_fallback else [models[0]]
        if not allow_fallback and len(models) > 1:
            chain = [models[0]]
        last: BaseException | None = None
        for m_idx, model in enumerate(chain):
            is_last_model = m_idx == len(chain) - 1
            for attempt in range(ma):
                try:
                    return per_model(model)
                except BaseException as exc:
                    last = exc
                    if not is_transient_gemini_error(exc):
                        raise
                    is_last_attempt = attempt == ma - 1
                    if is_last_model and is_last_attempt:
                        raise
                    sec = _sleep_for_transient(exc, attempt, base_delay=bd, max_delay=md, rate_limit_delay=rl)
                    if on_retry is not None:
                        on_retry(attempt + 1, model, exc, sec)
                    else:
                        logger.warning(
                            "Gemini transient error (model=%s attempt %s/%s): %s; sleeping %.1fs",
                            model,
                            attempt + 1,
                            ma,
                            exc,
                            sec,
                        )
                    sleep(sec)
                    if is_last_attempt and not is_last_model:
                        break
        assert last is not None
        raise last

    if fn is None:
        raise ValueError("invoke_with_transient_retry: pass fn=... or per_model=... and models=...")

    last_fn: BaseException | None = None
    for attempt in range(ma):
        try:
            return fn()
        except BaseException as exc:
            last_fn = exc
            if not is_transient_gemini_error(exc) or attempt == ma - 1:
                raise
            sec = _sleep_for_transient(exc, attempt, base_delay=bd, max_delay=md, rate_limit_delay=rl)
            if on_retry is not None:
                on_retry(attempt + 1, None, exc, sec)
            else:
                logger.warning(
                    "Gemini transient error (attempt %s/%s): %s; sleeping %.1fs",
                    attempt + 1,
                    ma,
                    exc,
                    sec,
                )
            sleep(sec)
    assert last_fn is not None
    raise last_fn
