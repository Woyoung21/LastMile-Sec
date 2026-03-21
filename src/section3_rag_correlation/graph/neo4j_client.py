"""Thin Neo4j driver wrapper and schema application."""

from __future__ import annotations

from pathlib import Path

from neo4j import Driver, GraphDatabase

from src.section3_rag_correlation import config

_SCHEMA_PATH = Path(__file__).resolve().parent / "schema.cypher"


def get_driver() -> Driver:
    return GraphDatabase.driver(
        config.NEO4J_URI,
        auth=(config.NEO4J_USER, config.NEO4J_PASSWORD),
    )


def _split_cypher_statements(text: str) -> list[str]:
    """Split schema file on semicolons; strip comments and blanks."""
    stripped = []
    for block in text.split(";"):
        lines = []
        for line in block.splitlines():
            s = line.strip()
            if not s or s.startswith("//"):
                continue
            lines.append(line)
        if lines:
            stripped.append("\n".join(lines).strip())
    return stripped


def apply_schema(driver: Driver, database: str | None = None) -> None:
    """Apply schema.cypher (constraints + vector index)."""
    raw = _SCHEMA_PATH.read_text(encoding="utf-8")
    statements = _split_cypher_statements(raw)
    db = database or "neo4j"
    with driver.session(database=db) as session:
        for stmt in statements:
            session.run(stmt)


def verify_vector_index_online(driver: Driver, database: str | None = None) -> None:
    """Fail fast if vector index is not ONLINE (optional)."""
    db = database or "neo4j"
    q = """
    SHOW VECTOR INDEXES
    YIELD name, state
    WHERE name = $name
    RETURN state
    """
    with driver.session(database=db) as session:
        row = session.run(q, name=config.NEO4J_VECTOR_INDEX_NAME).single()
        if row and row["state"] != "ONLINE":
            raise RuntimeError(
                f"Vector index {config.NEO4J_VECTOR_INDEX_NAME} state={row['state']!r}; wait until ONLINE."
            )
