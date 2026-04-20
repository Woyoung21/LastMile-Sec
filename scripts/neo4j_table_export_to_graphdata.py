#!/usr/bin/env python3
"""
Convert a Neo4j Browser / table JSON export into lastmile-ui GraphData.

Input: JSON array of objects with keys:
  vendor, cid, steps, mitre_ids
(as produced by:
  MATCH (v:Vendor)-[:PROVIDES]->(c:Control)
  OPTIONAL MATCH (c)-[:MITIGATES]->(m:Mitre)
  RETURN v.name AS vendor, c.control_id AS cid, c.remediation_steps AS steps,
         collect(DISTINCT m.technique_id) AS mitre_ids
)

Output: mockGraphData.json shape { "nodes": [...], "links": [...] }

Run from repo root:
  python scripts/neo4j_table_export_to_graphdata.py \\
    --input lastmile-ui/src/data/neo4j_query_table_data_2026-4-19.json \\
    --output lastmile-ui/src/data/mockGraphData.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from neo4j_graphdata_lib import load_rows_from_json_text, table_rows_to_graphdata


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description="Neo4j table JSON -> lastmile-ui graph JSON")
    p.add_argument(
        "--input",
        "-i",
        type=Path,
        default=repo / "lastmile-ui" / "src" / "data" / "neo4j_query_table_data_2026-4-19.json",
        help="Path to tabular JSON export (array of rows)",
    )
    p.add_argument(
        "--output",
        "-o",
        type=Path,
        default=repo / "lastmile-ui" / "src" / "data" / "mockGraphData.json",
        help="Output path for GraphData JSON",
    )
    p.add_argument(
        "--max-desc-len",
        type=int,
        default=2000,
        help="Truncate control remediation text in node descriptions",
    )
    p.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="If > 0, only process the first N rows (smoke test)",
    )
    args = p.parse_args()

    in_path: Path = args.input
    if not in_path.is_file():
        raise SystemExit(f"Input not found: {in_path}")

    rows = load_rows_from_json_text(in_path.read_text(encoding="utf-8"))
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    data = table_rows_to_graphdata(rows, max_desc_len=args.max_desc_len)
    out_path: Path = args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    n_nodes = len(data["nodes"])
    n_links = len(data["links"])
    print(f"Wrote {out_path}")
    print(f"  nodes={n_nodes} links={n_links} (from {len(rows)} rows)")


if __name__ == "__main__":
    main()
