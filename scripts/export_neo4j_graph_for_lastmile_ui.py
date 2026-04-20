#!/usr/bin/env python3
"""
Optional: read Vendor/Control/Mitre from Neo4j Bolt and write lastmile-ui GraphData JSON.

Uses the same Cypher as the Browser table export and the same mapping as
neo4j_table_export_to_graphdata.py (via neo4j_graphdata_lib).

Requires repo-root .env with NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD (see Section 3 config).

Run from repo root:
  python scripts/export_neo4j_graph_for_lastmile_ui.py -o lastmile-ui/src/data/mockGraphData.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from neo4j_graphdata_lib import table_rows_to_graphdata

CYPHER = """
MATCH (v:Vendor)-[:PROVIDES]->(c:Control)
OPTIONAL MATCH (c)-[:MITIGATES]->(m:Mitre)
RETURN v.name AS vendor,
       c.control_id AS cid,
       c.remediation_steps AS steps,
       collect(DISTINCT m.technique_id) AS mitre_ids
"""


def main() -> None:
    from src.section3_rag_correlation.graph.neo4j_client import get_driver

    p = argparse.ArgumentParser(description="Neo4j Bolt -> lastmile-ui mockGraphData.json")
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=REPO_ROOT / "lastmile-ui" / "src" / "data" / "mockGraphData.json",
        help="Output GraphData JSON path",
    )
    p.add_argument("--max-desc-len", type=int, default=2000)
    p.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="If > 0, truncate to first N rows after query",
    )
    args = p.parse_args()

    driver = get_driver()
    try:
        with driver.session() as session:
            result = session.run(CYPHER)
            rows = [dict(r) for r in result]
    finally:
        driver.close()

    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    data = table_rows_to_graphdata(rows, max_desc_len=args.max_desc_len)
    out: Path = args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Wrote {out}")
    print(f"  nodes={len(data['nodes'])} links={len(data['links'])} (from {len(rows)} rows)")


if __name__ == "__main__":
    main()
