"""Sanity checks for correlation Cypher (no live Neo4j required)."""

import pytest

from src.section3_rag_correlation.correlation.three_way_filter import (
    normalized_tech_stack,
    three_way_query_cypher,
)


def test_three_way_query_contains_expected_clauses() -> None:
    q = three_way_query_cypher()
    assert "CALL db.index.vector.queryNodes(" in q
    assert "control_remediation_vector" in q
    assert "MITIGATES" in q and "PROVIDES" in q
    assert "LIMIT 1" in q
    assert "$queryEmbedding" in q and "$mitreIds" in q
    assert "$allowedVendorNamesLower" in q


def test_normalized_tech_stack_lowercase_trim() -> None:
    assert normalized_tech_stack([" Windows ", "Meraki"]) == ["windows", "meraki"]


def test_invalid_vector_index_name_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.section3_rag_correlation.correlation.three_way_filter.config.NEO4J_VECTOR_INDEX_NAME",
        "bad-name!",
    )
    with pytest.raises(ValueError, match="NEO4J_VECTOR_INDEX_NAME"):
        three_way_query_cypher()
