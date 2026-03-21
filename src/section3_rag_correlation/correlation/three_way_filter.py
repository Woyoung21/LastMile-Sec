"""
Three-way filter: structural + environmental + semantic in a single Cypher query.

Python only embeds technical_summary (768-d) and passes parameters.
No Python-side semantic re-ranking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from neo4j import Driver

from src.section3_rag_correlation import config
from src.section3_rag_correlation.correlation.enriched_input import EnrichedFinding
from src.section3_rag_correlation.llm import assert_embedding_dim, get_embeddings

_INDEX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _validated_vector_index_name() -> str:
    name = config.NEO4J_VECTOR_INDEX_NAME
    if not _INDEX_RE.match(name):
        raise ValueError(
            "NEO4J_VECTOR_INDEX_NAME must be alphanumeric/underscore (Neo4j index name); "
            f"got {name!r}"
        )
    return name


def three_way_query_cypher() -> str:
    """Build unified Cypher with a validated literal index name (matches schema.cypher)."""
    idx = _validated_vector_index_name()
    # db.index.vector.queryNodes — Neo4j 5.13+; index name must match CREATE VECTOR INDEX.
    return f"""
CALL db.index.vector.queryNodes('{idx}', $k, $queryEmbedding)
YIELD node AS c, score
WHERE c:Control
MATCH (c)-[:MITIGATES]->(m:Mitre)
WHERE m.technique_id IN $mitreIds
MATCH (v:Vendor)-[:PROVIDES]->(c)
WHERE toLower(v.name) IN $allowedVendorNamesLower
   OR (c.vendor_product IS NOT NULL AND toLower(c.vendor_product) IN $allowedVendorNamesLower)
RETURN c AS control, v AS vendor, score AS similarity
ORDER BY similarity DESC
LIMIT 1
"""


def _node_to_dict(node: Any) -> dict[str, Any] | None:
    if node is None:
        return None
    return {k: node[k] for k in node.keys()}


@dataclass
class CorrelationResult:
    control: dict[str, Any] | None
    vendor: dict[str, Any] | None
    similarity: float | None
    query_embedding_dims: int


def normalized_tech_stack(entries: list[str]) -> list[str]:
    return [e.strip().lower() for e in entries if e and e.strip()]


def correlate_finding(
    driver: Driver,
    finding: EnrichedFinding,
    *,
    tech_stack: list[str] | None = None,
    vector_top_k: int | None = None,
    database: str | None = None,
) -> CorrelationResult:
    """
    Run one unified Cypher query for the finding.

    Embeds ``technical_summary`` with gemini-embedding-001 at 768 dimensions (RETRIEVAL_QUERY).
    """
    embedder = get_embeddings()
    vec = embedder.embed_query(finding.technical_summary)
    assert_embedding_dim(vec)

    allowed = normalized_tech_stack(tech_stack or config.GLOBAL_TECH_STACK)
    k = vector_top_k or config.VECTOR_QUERY_TOP_K
    db = database or "neo4j"

    params: dict[str, Any] = {
        "k": k,
        "queryEmbedding": vec,
        "mitreIds": finding.mitre_ids,
        "allowedVendorNamesLower": allowed,
    }

    with driver.session(database=db) as session:
        record = session.run(three_way_query_cypher(), **params).single()

    if not record:
        return CorrelationResult(
            control=None, vendor=None, similarity=None, query_embedding_dims=len(vec)
        )

    c = record["control"]
    v = record["vendor"]
    sim = record["similarity"]
    return CorrelationResult(
        control=_node_to_dict(c),
        vendor=_node_to_dict(v),
        similarity=float(sim) if sim is not None else None,
        query_embedding_dims=len(vec),
    )
