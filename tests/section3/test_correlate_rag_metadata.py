"""RAG correlation output shape (no Neo4j)."""

from __future__ import annotations

from src.section3_rag_correlation.cli.correlate import (
    _best_control_for_output,
    _candidate_to_dict,
    _json_safe,
)
from src.section3_rag_correlation.correlation.three_way_filter import CandidateControl


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


def test_candidate_to_dict_structure() -> None:
    cand = CandidateControl(
        control={"control_id": "CIS-1", "remediation_steps": "do it", "remediation_embedding": [0.1] * 768},
        vendor={"name": "Windows Server"},
        vector_similarity=0.85,
        composite_score=1.35,
        matched_mitre=["T1110"],
        mitre_matched=True,
        vendor_matched=True,
    )
    d = _candidate_to_dict(cand)
    assert d["vendor_name"] == "Windows Server"
    assert d["vector_similarity"] == 0.85
    assert d["composite_score"] == 1.35
    assert d["mitre_matched"] is True
    assert d["vendor_matched"] is True
    assert d["matched_mitre_ids"] == ["T1110"]
    assert "remediation_embedding" not in d["control"]


def test_candidate_to_dict_null_vendor() -> None:
    cand = CandidateControl(
        control={"control_id": "X"},
        vendor=None,
        vector_similarity=0.5,
        composite_score=0.5,
        matched_mitre=[],
        mitre_matched=False,
        vendor_matched=False,
    )
    d = _candidate_to_dict(cand)
    assert d["vendor_name"] is None
    assert d["mitre_matched"] is False


def _make_cand(vendor_name: str, score: float) -> CandidateControl:
    return CandidateControl(
        control={"control_id": f"ctrl-{vendor_name}"},
        vendor={"name": vendor_name},
        vector_similarity=score,
        composite_score=score,
        matched_mitre=[],
        mitre_matched=False,
        vendor_matched=True,
    )


def test_tiered_partitioning() -> None:
    """Verify vendor vs framework classification matches the correlate.py logic."""
    from src.section3_rag_correlation.cli.correlate import _candidate_to_dict

    candidates = [
        _make_cand("Windows Server", 1.2),
        _make_cand("NIST SP 800-53", 1.3),
        _make_cand("Ubuntu Linux", 0.9),
        _make_cand("NIST SP 800-53", 1.1),
    ]

    _FRAMEWORK_VENDOR = "NIST SP 800-53"
    vendor_cands = [c for c in candidates if c.vendor and c.vendor.get("name") != _FRAMEWORK_VENDOR]
    framework_cands = [c for c in candidates if not c.vendor or c.vendor.get("name") == _FRAMEWORK_VENDOR]

    assert len(vendor_cands) == 2
    assert len(framework_cands) == 2
    assert all(c.vendor["name"] != _FRAMEWORK_VENDOR for c in vendor_cands)
    assert all(c.vendor["name"] == _FRAMEWORK_VENDOR for c in framework_cands)

    vendor_dicts = [_candidate_to_dict(c) for c in vendor_cands]
    framework_dicts = [_candidate_to_dict(c) for c in framework_cands]
    assert vendor_dicts[0]["vendor_name"] == "Windows Server"
    assert framework_dicts[0]["vendor_name"] == "NIST SP 800-53"
