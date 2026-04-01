"""
Three-way filter: structural + environmental + semantic in a single Cypher query.

Uses OPTIONAL MATCH so MITRE / vendor gates degrade gracefully (boost scoring)
instead of hard-AND filtering that drops results entirely.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from neo4j import Driver

from src.section3_rag_correlation import config
from src.section3_rag_correlation.correlation.enriched_input import EnrichedFinding
from src.section3_rag_correlation.llm import assert_embedding_dim, get_embeddings

_INDEX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

MITRE_BOOST = 0.3
VENDOR_BOOST = 0.2
SPECIFICITY_BONUS = 0.05
DEFAULT_TOP_N = 5


def _validated_vector_index_name() -> str:
    name = config.NEO4J_VECTOR_INDEX_NAME
    if not _INDEX_RE.match(name):
        raise ValueError(
            "NEO4J_VECTOR_INDEX_NAME must be alphanumeric/underscore (Neo4j index name); "
            f"got {name!r}"
        )
    return name


def three_way_query_cypher() -> str:
    """Composite-scored Cypher: vector similarity + MITRE boost + vendor boost, top-N."""
    idx = _validated_vector_index_name()
    return f"""
CALL db.index.vector.queryNodes('{idx}', $k, $queryEmbedding)
YIELD node AS c, score
WHERE c:Control

OPTIONAL MATCH (c)-[:MITIGATES]->(m:Mitre)
  WHERE m.technique_id IN $mitreIds

WITH c, score, collect(DISTINCT m.technique_id) AS matched_mitre

OPTIONAL MATCH (v:Vendor)-[:PROVIDES]->(c)

WITH c, score, matched_mitre, collect(DISTINCT v) AS vendors

WITH c, score, matched_mitre, vendors,
     head(vendors) AS v,
     CASE WHEN size(matched_mitre) > 0 AND $mitreIdCount > 0
       THEN $mitreBoost * (toFloat(size(matched_mitre)) / toFloat($mitreIdCount))
       ELSE 0.0 END AS mitre_boost,
     CASE WHEN any(vv IN vendors WHERE toLower(vv.name) IN $allowedVendorNamesLower)
       OR any(vv IN vendors WHERE any(tok IN $allowedVendorNamesLower WHERE toLower(vv.name) CONTAINS tok))
       OR (c.vendor_product IS NOT NULL AND toLower(c.vendor_product) IN $allowedVendorNamesLower)
       OR (c.vendor_product IS NOT NULL AND any(tok IN $allowedVendorNamesLower WHERE toLower(c.vendor_product) CONTAINS tok))
       THEN $vendorBoost ELSE 0.0 END AS vendor_boost

WITH c, v, score, matched_mitre, mitre_boost, vendor_boost,
     CASE WHEN v IS NOT NULL AND toLower(v.name) <> 'nist sp 800-53'
       THEN $specificityBonus ELSE 0.0 END AS specificity_bonus,
     score + mitre_boost + vendor_boost AS base_score

WITH c, v, score, matched_mitre, mitre_boost, vendor_boost, specificity_bonus,
     base_score + specificity_bonus AS composite_score

RETURN c AS control, v AS vendor,
       score AS vector_similarity,
       composite_score,
       matched_mitre,
       mitre_boost > 0 AS mitre_matched,
       vendor_boost > 0 AS vendor_matched
ORDER BY composite_score DESC
LIMIT $topN
"""


def _node_to_dict(node: Any) -> dict[str, Any] | None:
    if node is None:
        return None
    return {k: node[k] for k in node.keys()}


@dataclass
class CandidateControl:
    """One ranked candidate from the composite Cypher query."""

    control: dict[str, Any] | None
    vendor: dict[str, Any] | None
    vector_similarity: float | None
    composite_score: float | None
    matched_mitre: list[str]
    mitre_matched: bool
    vendor_matched: bool


@dataclass
class CorrelationResult:
    candidates: list[CandidateControl] = field(default_factory=list)
    query_embedding_dims: int = 0

    @property
    def best(self) -> CandidateControl | None:
        return self.candidates[0] if self.candidates else None

    @property
    def control(self) -> dict[str, Any] | None:
        b = self.best
        return b.control if b else None

    @property
    def vendor(self) -> dict[str, Any] | None:
        b = self.best
        return b.vendor if b else None

    @property
    def similarity(self) -> float | None:
        b = self.best
        return b.vector_similarity if b else None


def normalized_tech_stack(entries: list[str]) -> list[str]:
    return [e.strip().lower() for e in entries if e and e.strip()]


def _build_query_text(finding: EnrichedFinding) -> str:
    """Bridge the observation→remediation semantic gap in the embedding query."""
    parts = [f"Security control to remediate: {finding.technical_summary}"]
    if finding.mitre_ids:
        parts.append(f"MITRE ATT&CK techniques: {', '.join(finding.mitre_ids)}.")
    return " ".join(parts)


_STOPWORDS = frozenset(
    "a an the is are was were be been being have has had do does did will would "
    "shall should may might can could of in to for on with at by from as into "
    "through during before after above below between out off over under again "
    "further then once that this these those it its and but or nor not no so if "
    "all any both each few more most other some such very just also how when where "
    "which who whom what why connection indicates suspicious network activity port "
    "set configured ensure disabled enabled".split()
)


def _token_set(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) > 2 and w not in _STOPWORDS}


RELEVANCE_PENALTY = 0.15


def rerank_candidates(
    candidates: list[CandidateControl],
    finding: EnrichedFinding,
) -> list[CandidateControl]:
    """Re-score candidates by penalizing those with zero keyword overlap with the finding."""
    if not candidates:
        return candidates

    finding_tokens = _token_set(finding.technical_summary)
    if not finding_tokens:
        return candidates

    for cand in candidates:
        remediation = ""
        if cand.control:
            remediation = cand.control.get("remediation_steps") or ""
            remediation += " " + (cand.control.get("control_id") or "")
        cand_tokens = _token_set(remediation)
        overlap = finding_tokens & cand_tokens
        if not overlap and cand.composite_score is not None:
            cand.composite_score = cand.composite_score - RELEVANCE_PENALTY

    candidates.sort(key=lambda c: c.composite_score or 0.0, reverse=True)
    return candidates


def correlate_finding(
    driver: Driver,
    finding: EnrichedFinding,
    *,
    tech_stack: list[str] | None = None,
    vector_top_k: int | None = None,
    top_n: int | None = None,
    database: str | None = None,
) -> CorrelationResult:
    """
    Run composite-scored Cypher and return top-N candidates.

    Embeds a reformulated query with gemini-embedding-001 at 768 dimensions (RETRIEVAL_QUERY).
    """
    embedder = get_embeddings()
    query_text = _build_query_text(finding)
    vec = embedder.embed_query(query_text)
    assert_embedding_dim(vec)

    allowed = normalized_tech_stack(tech_stack or config.GLOBAL_TECH_STACK)
    k = vector_top_k or config.VECTOR_QUERY_TOP_K
    n = top_n or DEFAULT_TOP_N
    db = database or "neo4j"

    params: dict[str, Any] = {
        "k": k,
        "queryEmbedding": vec,
        "mitreIds": finding.mitre_ids,
        "mitreIdCount": len(finding.mitre_ids),
        "allowedVendorNamesLower": allowed,
        "mitreBoost": MITRE_BOOST,
        "vendorBoost": VENDOR_BOOST,
        "specificityBonus": SPECIFICITY_BONUS,
        "topN": n,
    }

    with driver.session(database=db) as session:
        records = list(session.run(three_way_query_cypher(), **params))

    candidates: list[CandidateControl] = []
    for rec in records:
        candidates.append(
            CandidateControl(
                control=_node_to_dict(rec["control"]),
                vendor=_node_to_dict(rec["vendor"]),
                vector_similarity=float(rec["vector_similarity"]) if rec["vector_similarity"] is not None else None,
                composite_score=float(rec["composite_score"]) if rec["composite_score"] is not None else None,
                matched_mitre=list(rec["matched_mitre"] or []),
                mitre_matched=bool(rec["mitre_matched"]),
                vendor_matched=bool(rec["vendor_matched"]),
            )
        )

    candidates = rerank_candidates(candidates, finding)
    return CorrelationResult(candidates=candidates, query_embedding_dims=len(vec))
