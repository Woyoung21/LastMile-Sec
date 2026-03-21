"""RAG correlation output shape (no Neo4j)."""

from __future__ import annotations

from src.section3_rag_correlation.cli.correlate import _best_control_for_output, _json_safe


def test_best_control_strips_remediation_embedding() -> None:
    ctrl = {
        "control_id": "X-1",
        "remediation_steps": "fix",
        "remediation_embedding": [0.1] * 768,
    }
    out = _best_control_for_output(ctrl)
    assert out is not None
    assert "remediation_embedding" not in out
    assert out["control_id"] == "X-1"
    assert len(ctrl["remediation_embedding"]) == 768


def test_best_control_none() -> None:
    assert _best_control_for_output(None) is None


def test_json_safe_neo4j_datetime_like() -> None:
    class FakeNeo:
        def iso_format(self) -> str:
            return "2024-06-01T12:00:00Z"

    FakeNeo.__module__ = "neo4j.time"
    assert _json_safe(FakeNeo()) == "2024-06-01T12:00:00Z"


def test_best_control_json_safe_nested_neo4j_time() -> None:
    class FakeNeo:
        def iso_format(self) -> str:
            return "2024-01-01T00:00:00Z"

    FakeNeo.__module__ = "neo4j.time"
    ctrl = {
        "control_id": "X",
        "created_at": FakeNeo(),
        "remediation_embedding": [0.0],
    }
    out = _best_control_for_output(ctrl)
    assert out is not None
    assert out["created_at"] == "2024-01-01T00:00:00Z"
    assert "remediation_embedding" not in out
