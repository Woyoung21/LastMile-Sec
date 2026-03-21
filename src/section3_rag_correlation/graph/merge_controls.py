"""MERGE Control, Vendor, Mitre and relationships — idempotent writes."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from src.section3_rag_correlation import config
from src.section3_rag_correlation.schemas import SecurityControl


def merge_security_control(
    driver: Driver,
    control: SecurityControl,
    embedding: list[float],
    database: str | None = None,
) -> None:
    """Persist one SecurityControl and its MITRE edges using MERGE only."""
    if len(embedding) != config.EMBEDDING_DIMENSIONS:
        raise ValueError(
            f"embedding must have length {config.EMBEDDING_DIMENSIONS}, got {len(embedding)}"
        )

    vendor_name = (control.vendor_product or "unknown").strip()
    mitre_ids = [m.strip() for m in (control.mitre_mapping or []) if m and m.strip()]

    db = database or "neo4j"
    base = """
    MERGE (v:Vendor {name: $vendor_name})
    ON CREATE SET v.created_at = datetime()
    SET v.updated_at = datetime()

    MERGE (c:Control {control_id: $control_id})
    ON CREATE SET c.created_at = datetime()
    SET c.remediation_steps = $remediation_steps,
        c.audit_procedure = $audit_procedure,
        c.vendor_product = $vendor_product,
        c.remediation_embedding = $embedding,
        c.updated_at = datetime()

    MERGE (v)-[pv:PROVIDES]->(c)
    SET pv.updated_at = datetime()
    """

    params: dict[str, Any] = {
        "vendor_name": vendor_name,
        "control_id": control.control_id.strip(),
        "remediation_steps": control.remediation_steps,
        "audit_procedure": control.audit_procedure,
        "vendor_product": control.vendor_product,
        "embedding": embedding,
    }

    with driver.session(database=db) as session:
        session.run(base, **params)
        if mitre_ids:
            session.run(
                """
                MATCH (c:Control {control_id: $control_id})
                UNWIND $mitre_ids AS mid
                MERGE (m:Mitre {technique_id: mid})
                ON CREATE SET m.created_at = datetime()
                SET m.updated_at = datetime()
                MERGE (c)-[r:MITIGATES]->(m)
                SET r.updated_at = datetime()
                """,
                control_id=params["control_id"],
                mitre_ids=mitre_ids,
            )
