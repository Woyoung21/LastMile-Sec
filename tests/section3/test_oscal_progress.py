"""OSCAL progress log resume (no Neo4j)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.section3_rag_correlation.ingestion.progress import (
    OscalProgressEntry,
    append_oscal_progress,
    load_completed_oscal_join_keys,
)


@pytest.fixture
def no_ensure_log_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.section3_rag_correlation.ingestion.progress.config.ensure_log_dir",
        lambda: None,
    )


def test_load_oscal_done_empty(tmp_path: Path, no_ensure_log_dir: None) -> None:
    log = tmp_path / "o.log"
    cat = (tmp_path / "catalog.json").resolve()
    assert load_completed_oscal_join_keys(log, cat) == set()


def test_oscal_ok_and_skipped_count_as_done(tmp_path: Path, no_ensure_log_dir: None) -> None:
    log = tmp_path / "o.log"
    cat = (tmp_path / "nist.json").resolve()
    key = str(cat)
    append_oscal_progress(
        log,
        OscalProgressEntry(catalog_path=key, join_key="AC-01", status="ok"),
    )
    append_oscal_progress(
        log,
        OscalProgressEntry(
            catalog_path=key,
            join_key="AC-02",
            status="skipped",
            detail="no prose",
        ),
    )
    assert load_completed_oscal_join_keys(log, cat) == {"AC-01", "AC-02"}


def test_error_status_not_done(tmp_path: Path, no_ensure_log_dir: None) -> None:
    log = tmp_path / "o.log"
    cat = (tmp_path / "nist.json").resolve()
    key = str(cat)
    append_oscal_progress(
        log,
        OscalProgressEntry(
            catalog_path=key,
            join_key="AC-03",
            status="error",
            detail="neo4j",
        ),
    )
    assert load_completed_oscal_join_keys(log, cat) == set()


def test_other_catalog_ignored(tmp_path: Path, no_ensure_log_dir: None) -> None:
    log = tmp_path / "o.log"
    cat_a = (tmp_path / "a.json").resolve()
    cat_b = (tmp_path / "b.json").resolve()
    append_oscal_progress(
        log,
        OscalProgressEntry(catalog_path=str(cat_a), join_key="AC-01", status="ok"),
    )
    assert load_completed_oscal_join_keys(log, cat_b) == set()
    assert load_completed_oscal_join_keys(log, cat_a) == {"AC-01"}
