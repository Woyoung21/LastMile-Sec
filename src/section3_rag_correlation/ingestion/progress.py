"""Append-only progress log for resumable PDF and OSCAL JSON ingestion."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from src.section3_rag_correlation import config


@dataclass
class ProgressEntry:
    pdf_path: str
    batch_index: int
    start_page: int
    end_page: int
    status: str
    detail: str | None = None


@dataclass
class OscalProgressEntry:
    """One OSCAL control written (or failed) during JSON ingest."""

    catalog_path: str
    join_key: str
    status: str
    detail: str | None = None


def _normalize_pdf_key(path: Path) -> str:
    return str(path.resolve())


def load_completed_batch_indices(log_path: Path, pdf_path: Path) -> set[int]:
    """Return batch_index values already completed successfully for this PDF."""
    key = _normalize_pdf_key(pdf_path)
    done: set[int] = set()
    if not log_path.is_file():
        return done
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("pdf") != key:
            continue
        if row.get("status") == "ok" and "batch_index" in row:
            done.add(int(row["batch_index"]))
    return done


def _normalize_catalog_key(path: Path) -> str:
    return str(path.resolve())


def load_completed_oscal_join_keys(log_path: Path, catalog_path: Path) -> set[str]:
    """Return join_key values already completed successfully for this OSCAL catalog file."""
    key = _normalize_catalog_key(catalog_path)
    done: set[str] = set()
    if not log_path.is_file():
        return done
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("kind") != "oscal":
            continue
        if row.get("catalog") != key:
            continue
        st = row.get("status")
        if st in ("ok", "skipped") and row.get("join_key"):
            done.add(str(row["join_key"]))
    return done


def append_oscal_progress(log_path: Path, entry: OscalProgressEntry) -> None:
    config.ensure_log_dir()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "kind": "oscal",
        "catalog": entry.catalog_path,
        "join_key": entry.join_key,
        "status": entry.status,
        "detail": entry.detail,
    }
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def append_progress(log_path: Path, entry: ProgressEntry) -> None:
    config.ensure_log_dir()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "pdf": entry.pdf_path,
        "batch_index": entry.batch_index,
        "start_page": entry.start_page,
        "end_page": entry.end_page,
        "status": entry.status,
        "detail": entry.detail,
    }
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
