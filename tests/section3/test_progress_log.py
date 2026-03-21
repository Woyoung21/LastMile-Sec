"""Resume / progress log behavior (no Neo4j)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.section3_rag_correlation.ingestion.progress import (
    ProgressEntry,
    append_progress,
    load_completed_batch_indices,
)


@pytest.fixture
def no_ensure_log_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid creating repo data/logs during tests."""
    monkeypatch.setattr(
        "src.section3_rag_correlation.ingestion.progress.config.ensure_log_dir",
        lambda: None,
    )


def test_load_completed_empty_when_no_file(tmp_path: Path, no_ensure_log_dir: None) -> None:
    log = tmp_path / "missing.log"
    pdf = tmp_path / "doc.pdf"
    assert load_completed_batch_indices(log, pdf) == set()


def test_append_then_load_roundtrip(tmp_path: Path, no_ensure_log_dir: None) -> None:
    log = tmp_path / "p.log"
    pdf = (tmp_path / "sample.pdf").resolve()
    append_progress(
        log,
        ProgressEntry(
            pdf_path=str(pdf),
            batch_index=0,
            start_page=0,
            end_page=4,
            status="ok",
        ),
    )
    append_progress(
        log,
        ProgressEntry(
            pdf_path=str(pdf),
            batch_index=1,
            start_page=5,
            end_page=9,
            status="ok",
        ),
    )
    assert load_completed_batch_indices(log, pdf) == {0, 1}


def test_error_status_not_counted_as_completed(tmp_path: Path, no_ensure_log_dir: None) -> None:
    log = tmp_path / "p.log"
    pdf = (tmp_path / "a.pdf").resolve()
    append_progress(
        log,
        ProgressEntry(
            pdf_path=str(pdf),
            batch_index=0,
            start_page=0,
            end_page=4,
            status="error",
            detail="boom",
        ),
    )
    assert load_completed_batch_indices(log, pdf) == set()


def test_other_pdf_ignored(tmp_path: Path, no_ensure_log_dir: None) -> None:
    log = tmp_path / "p.log"
    pdf_a = (tmp_path / "a.pdf").resolve()
    pdf_b = (tmp_path / "b.pdf").resolve()
    append_progress(
        log,
        ProgressEntry(
            pdf_path=str(pdf_a),
            batch_index=0,
            start_page=0,
            end_page=4,
            status="ok",
        ),
    )
    assert load_completed_batch_indices(log, pdf_b) == set()
    assert load_completed_batch_indices(log, pdf_a) == {0}


def test_malformed_lines_skipped(tmp_path: Path, no_ensure_log_dir: None) -> None:
    log = tmp_path / "p.log"
    pdf = (tmp_path / "x.pdf").resolve()
    log.write_text("not json\n", encoding="utf-8")
    append_progress(
        log,
        ProgressEntry(
            pdf_path=str(pdf),
            batch_index=2,
            start_page=10,
            end_page=14,
            status="ok",
        ),
    )
    assert load_completed_batch_indices(log, pdf) == {2}
