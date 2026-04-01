"""Load environment and resolved paths for Section 3."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load repo-root .env when present
_REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_REPO_ROOT / ".env")


def _path_from_env(key: str, default: str) -> Path:
    return (_REPO_ROOT / os.environ.get(key, default)).resolve()


def _int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except ValueError:
        return default


def _tech_stack_list(raw: str) -> list[str]:
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return parts


# --- Gemini / LangChain ---
GOOGLE_API_KEY: str | None = os.environ.get("GOOGLE_API_KEY")
GEMINI_MODEL: str = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
# Vector size for Neo4j index + gemini-embedding-001 (output_dimensionality). Not env-overridden.
# Embedding implementation: see embeddings_gemini.py (google.genai Client; not LangChain GoogleGenerativeAIEmbeddings).
EMBEDDING_DIMENSIONS: int = 768

# --- Neo4j ---
NEO4J_URI: str = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER: str = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD: str = os.environ.get("NEO4J_PASSWORD", "changeme")
NEO4J_VECTOR_INDEX_NAME: str = os.environ.get(
    "NEO4J_VECTOR_INDEX_NAME", "control_remediation_vector"
)

# --- Directories ---
RAG_CORPUS_DIR: Path = _path_from_env("RAG_CORPUS_DIR", "data/raw/RAG_Corpus")
ENRICHED_JSON_DIR: Path = _path_from_env("ENRICHED_JSON_DIR", "data/mapped")
CORRELATED_JSON_DIR: Path = _path_from_env("CORRELATED_JSON_DIR", "data/correlate")
LOG_DIR: Path = _path_from_env("LOG_DIR", "data/logs")
PROCESSED_PAGES_LOG: Path = LOG_DIR / "processed_pages.log"
PROCESSED_OSCAL_LOG: Path = LOG_DIR / "processed_oscal_controls.log"

# --- Ingestion ---
PAGE_BATCH_SIZE: int = _int("PAGE_BATCH_SIZE", 5)
VECTOR_QUERY_TOP_K: int = _int("VECTOR_QUERY_TOP_K", 100)

# --- Correlation ---
GLOBAL_TECH_STACK: list[str] = _tech_stack_list(
    os.environ.get("GLOBAL_TECH_STACK", "Windows Server,Meraki MS,M365,NIST SP 800-53")
)


def ensure_log_dir() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def ensure_correlated_dir() -> None:
    CORRELATED_JSON_DIR.mkdir(parents=True, exist_ok=True)
