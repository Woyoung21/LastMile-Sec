"""Load environment and resolved paths for Section 4."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

_REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_REPO_ROOT / ".env")


def _path_from_env(key: str, default: str) -> Path:
    return (_REPO_ROOT / os.environ.get(key, default)).resolve()


def _int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except ValueError:
        return default


def _float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, str(default)))
    except ValueError:
        return default


def _tech_stack_list(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


# --- Gemini / LangChain ---
GOOGLE_API_KEY: str | None = os.environ.get("GOOGLE_API_KEY")
GEMINI_MODEL: str = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

# --- Directories ---
CORRELATED_JSON_DIR: Path = _path_from_env("CORRELATED_JSON_DIR", "data/correlate")
REMEDIATED_JSON_DIR: Path = _path_from_env("REMEDIATED_JSON_DIR", "data/remediated")

# --- Tech stack (shared with Section 3) ---
GLOBAL_TECH_STACK: list[str] = _tech_stack_list(
    os.environ.get("GLOBAL_TECH_STACK", "Windows Server,Meraki MS,M365,NIST SP 800-53")
)

# --- Self-RAG thresholds ---
GROUNDING_THRESHOLD: float = _float("SELFRAG_GROUNDING_THRESHOLD", 0.7)
RELEVANCE_THRESHOLD: float = _float("SELFRAG_RELEVANCE_THRESHOLD", 0.5)
COMPLETENESS_THRESHOLD: float = _float("SELFRAG_COMPLETENESS_THRESHOLD", 0.5)
SUBSTEP_QUALITY_THRESHOLD: float = _float("SELFRAG_SUBSTEP_QUALITY_THRESHOLD", 0.7)
MAX_RETRIES: int = _int("SELFRAG_MAX_RETRIES", 2)

# --- Generation ---
PROMPT_VERSION: str = os.environ.get("REMEDIATION_PROMPT_VERSION", "remediation_v2")
LLM_TEMPERATURE: float = _float("REMEDIATION_LLM_TEMPERATURE", 0.2)

# --- Google Search grounding (Section 4 optional path; enable via CLI --enable-search-augmentation) ---
# Substrings matched against tech stack + finding text (case-insensitive).
_THIN_DEFAULT = "meraki,ubiquiti,ubnt,unifi,ui.com,edgeswitch,edglock"
THIN_CORPUS_VENDOR_SUBSTRINGS: list[str] = [
    s.strip().lower()
    for s in os.environ.get("SECTION4_THIN_CORPUS_VENDORS", _THIN_DEFAULT).split(",")
    if s.strip()
]
SEARCH_TRIGGER_SIMILARITY_MAX: float = _float("SECTION4_SEARCH_SIMILARITY_MAX", 0.42)
SEARCH_TRIGGER_COMPOSITE_MAX: float = _float("SECTION4_SEARCH_COMPOSITE_MAX", 0.48)


def ensure_remediated_dir() -> None:
    REMEDIATED_JSON_DIR.mkdir(parents=True, exist_ok=True)
