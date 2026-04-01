"""Sanity checks for correlation Cypher (no live Neo4j required)."""

import pytest

from src.section3_rag_correlation.correlation.three_way_filter import (
    CandidateControl,
    normalized_tech_stack,
    rerank_candidates,
    three_way_query_cypher,
    _build_query_text,
    MITRE_BOOST,
    VENDOR_BOOST,
    SPECIFICITY_BONUS,
    DEFAULT_TOP_N,
    RELEVANCE_PENALTY,
)
from src.section3_rag_correlation.correlation.enriched_input import EnrichedFinding
from pathlib import Path


def test_three_way_query_contains_expected_clauses() -> None:
    q = three_way_query_cypher()
    assert "CALL db.index.vector.queryNodes(" in q
    assert "control_remediation_vector" in q
    assert "MITIGATES" in q and "PROVIDES" in q
    assert "OPTIONAL MATCH" in q
    assert "$topN" in q
    assert "$queryEmbedding" in q and "$mitreIds" in q
    assert "$mitreIdCount" in q
    assert "$allowedVendorNamesLower" in q
    assert "$specificityBonus" in q
    assert "composite_score" in q
    assert "mitre_matched" in q
    assert "vendor_matched" in q
    assert "CONTAINS" in q
    assert "specificity_bonus" in q
    assert "nist sp 800-53" in q.lower()


def test_normalized_tech_stack_lowercase_trim() -> None:
    assert normalized_tech_stack([" Windows ", "Meraki"]) == ["windows", "meraki"]


def test_invalid_vector_index_name_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.section3_rag_correlation.correlation.three_way_filter.config.NEO4J_VECTOR_INDEX_NAME",
        "bad-name!",
    )
    with pytest.raises(ValueError, match="NEO4J_VECTOR_INDEX_NAME"):
        three_way_query_cypher()


def test_build_query_text_bridges_semantic_gap() -> None:
    f = EnrichedFinding(
        packet_source=Path("x.json"),
        finding_id="abc",
        technical_summary="RDP connection on port 3389",
        mitre_ids=["T1110", "T1563.002"],
    )
    text = _build_query_text(f)
    assert "Security control to remediate:" in text
    assert "RDP connection on port 3389" in text
    assert "T1110" in text
    assert "T1563.002" in text


def test_build_query_text_no_mitre() -> None:
    f = EnrichedFinding(
        packet_source=Path("x.json"),
        finding_id="abc",
        technical_summary="some event",
        mitre_ids=[],
    )
    text = _build_query_text(f)
    assert "Security control to remediate:" in text
    assert "MITRE" not in text


def test_boost_constants() -> None:
    assert MITRE_BOOST > 0
    assert VENDOR_BOOST > 0
    assert SPECIFICITY_BONUS > 0
    assert DEFAULT_TOP_N == 5


def _make_candidate(control_id: str, remediation: str, score: float) -> CandidateControl:
    return CandidateControl(
        control={"control_id": control_id, "remediation_steps": remediation},
        vendor={"name": "TestVendor"},
        vector_similarity=score,
        composite_score=score,
        matched_mitre=[],
        mitre_matched=False,
        vendor_matched=True,
    )


def test_rerank_penalizes_no_overlap() -> None:
    finding = EnrichedFinding(
        packet_source=Path("x.json"),
        finding_id="1",
        technical_summary="RDP brute force attack on port 3389",
        mitre_ids=["T1110"],
    )
    relevant = _make_candidate("RDP-1", "Deny logon through Remote Desktop Services RDP", 0.80)
    irrelevant = _make_candidate("NET-1", "Configure DNS zone transfer settings", 0.85)
    candidates = rerank_candidates([irrelevant, relevant], finding)
    assert candidates[0].control["control_id"] == "RDP-1"


def test_rerank_preserves_order_when_all_overlap() -> None:
    finding = EnrichedFinding(
        packet_source=Path("x.json"),
        finding_id="1",
        technical_summary="RDP brute force",
        mitre_ids=["T1110"],
    )
    c1 = _make_candidate("A", "RDP lockout brute force policy", 0.90)
    c2 = _make_candidate("B", "RDP session timeout brute", 0.80)
    candidates = rerank_candidates([c1, c2], finding)
    assert candidates[0].control["control_id"] == "A"
    assert candidates[1].control["control_id"] == "B"
