# lastmile-ui

Optional **Next.js** front end for visualizing LastMile-Sec outputs: MITRE ATT&CK views, remediation flows, and graph-style demos. It does **not** run the Python ingestion or pipeline CLIs; those live at the repository root (see the main [README.md](../README.md)).

## Prerequisites

- **Node.js** 18+ (LTS recommended)
- npm (ships with Node)

## Run locally

From this directory:

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The dev server uses Next.js App Router (`src/app/`).

## Build

```bash
npm run build
npm start
```

## Lint

```bash
npm run lint
```

## Relationship to the pipeline

- **Python pipeline** (Sections 1–4): `run.py`, `run_section2.py`, `run_pipeline.py`, and modules under `../src/`.
- **This app**: static/demo data under `src/data/` and UI components; use it to explore MITRE and remediation UX without wiring a full backend API unless you extend it.

A [Dockerfile](Dockerfile) is present if you containerize the UI for deployment.

## Correlation graph (Neo4j-scale)

The **Correlation** page reads [`src/data/mockGraphData.json`](src/data/mockGraphData.json) (`nodes` / `links` for [`CorrelationGraph`](src/components/CorrelationGraph.tsx)). To refresh it from your **real** Neo4j graph:

**Option A — Browser / table JSON (no Bolt script)**  
1. In Neo4j Browser, run:

```cypher
MATCH (v:Vendor)-[:PROVIDES]->(c:Control)
OPTIONAL MATCH (c)-[:MITIGATES]->(m:Mitre)
RETURN v.name AS vendor,
       c.control_id AS cid,
       c.remediation_steps AS steps,
       collect(DISTINCT m.technique_id) AS mitre_ids
```

2. Export the result as JSON (table / download). Save it under e.g. `src/data/neo4j_query_table_data_YYYY-M-D.json`.

3. From the **repository root**:

```bash
python scripts/neo4j_table_export_to_graphdata.py ^
  --input lastmile-ui/src/data/neo4j_query_table_data_YYYY-M-D.json ^
  --output lastmile-ui/src/data/mockGraphData.json
```

**Option B — Bolt (one command)**  
With `.env` containing `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`:

```bash
python scripts/export_neo4j_graph_for_lastmile_ui.py -o lastmile-ui/src/data/mockGraphData.json
```

Shared mapping logic lives in [`scripts/neo4j_graphdata_lib.py`](../scripts/neo4j_graphdata_lib.py). The older PDF-based generator [`scripts/build_mock_graph_from_corpus.py`](scripts/build_mock_graph_from_corpus.py) is only needed for offline demos without a Neo4j export.
