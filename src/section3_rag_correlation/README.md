# Section 3 — Hybrid GraphRAG (Gemini + Neo4j)

Ingest hardening guidance from PDFs and NIST OSCAL JSON into a Neo4j graph, then correlate Section 2 **mapped** findings (`data/mapped`) using a **composite-scored Cypher** query that combines vector similarity, MITRE ATT&CK matching, and vendor/tech-stack filtering — returning ranked top-N candidates per finding.

## Prerequisites

1. **Environment** — use the repo-root `.env`; ensure `GOOGLE_API_KEY` is set for Gemini. Merge Neo4j and path keys from a team **`.env.example`** if your project provides one (see root [README.md](../../README.md#local-only-configuration-files)). **Embeddings** use the Gemini API model **`gemini-embedding-001`** at **768** dimensions via [`embeddings_gemini.py`](embeddings_gemini.py) (`google.genai.Client.embed_content`). **Chat** extraction uses [`ChatGoogleGenerativeAI`](llm.py) from `langchain-google-genai`.
2. **Neo4j 5.13+** — vector indexes required. From repo root, if **`docker-compose.yml`** is present:

   ```bash
   docker compose up -d
   ```

   Default Bolt: `bolt://localhost:7687`, user `neo4j`, password `changeme` (match `NEO4J_PASSWORD` in `.env`).

3. **Dependencies** — single install from the project [`requirements.txt`](../../requirements.txt):

   ```bash
   pip install -r requirements.txt
   ```

## Commands

Run from the **repository root** (`LastMile-Sec`).

### Ingest PDFs

First run applies constraints and the 768-d vector index from `graph/schema.cypher`:

```bash
python -m src.section3_rag_correlation.cli.ingest
```

Options:

- `--corpus PATH` — override `RAG_CORPUS_DIR` (default `data/raw/RAG_Corpus`; set to `data/corpus` if your PDFs live there, or export `RAG_CORPUS_DIR`).
- `--no-schema` — skip applying `schema.cypher` (use if schema already applied).
- `--limit-pdfs N` / `--limit-batches N` — smoke-test without full corpus.

Progress / resume: `data/logs/processed_pages.log` (JSON lines per batch).

### Ingest NIST OSCAL JSON

Deterministic parse — no LLM extraction. Uses padded join keys + MITRE mapping file, stores `control_id` as `NIST-AC-01` style and `vendor_product` as `NIST SP 800-53`. Progress / resume: `data/logs/processed_oscal_controls.log`.

```bash
python -m src.section3_rag_correlation.cli.ingest_oscal \
  --oscal-catalog "data/corpus/NIST_SP-800-53_rev5_catalog.json" \
  --attack-mapping "data/corpus/nist_800_53-rev5_attack-16.1-enterprise_json.json"
```

The NIST↔ATT&CK mapping JSON may need to be downloaded separately; adjust `--attack-mapping` to its path on disk.

Options:

- `--attack-mapping PATH` — optional; omit to load controls without MITRE edges from this file.
- `--no-schema` — skip applying `schema.cypher`.
- `--limit-controls N` — merge at most N controls (smoke test).
- `--log PATH` — override progress log.

### Correlate

Correlates enriched JSON findings (default directory `data/mapped`). For each finding, the pipeline:

1. Embeds a **reformulated query** (`"Security control to remediate: {summary}. MITRE ATT&CK techniques: ..."`) to bridge the observation→remediation semantic gap.
2. Runs a **composite-scored Cypher** query with `OPTIONAL MATCH` for MITRE and vendor gates — no hard AND filtering. Each candidate receives a weighted score: `vector_similarity + mitre_boost (0.3) + vendor_boost (0.2)`.
3. Returns **top-N candidates** (default 3) ranked by composite score.
4. Applies a **keyword-overlap reranker** that penalizes candidates whose remediation text has zero token overlap with the finding.

Results are injected into `metadata.rag_correlation` and written to `data/correlate/` as `{original_stem}_correlated.json`.

```bash
python -m src.section3_rag_correlation.cli.correlate
```

Examples:

```bash
python -m src.section3_rag_correlation.cli.correlate --json "data/mapped/your_mapped.json" --max-findings 3
python -m src.section3_rag_correlation.cli.correlate --tech-stack "Windows Server,Ubuntu Linux,NIST SP 800-53"
```

Terminal output shows one line per finding with match flags:

```
[OK] Correlated abc-123 -> Windows Server (Score: 1.32 [MITRE+vendor])
```

### Output schema

Each correlated finding gets this structure in `metadata.rag_correlation`:

```json
{
  "similarity_score": 0.82,
  "composite_score": 1.32,
  "vendor_name": "Windows Server",
  "best_control": { "control_id": "...", "remediation_steps": "...", ... },
  "mitre_matched": true,
  "vendor_matched": true,
  "candidates": [
    {
      "vector_similarity": 0.82,
      "composite_score": 1.32,
      "mitre_matched": true,
      "vendor_matched": true,
      "matched_mitre_ids": ["T1110"],
      "vendor_name": "Windows Server",
      "control": { "control_id": "...", "remediation_steps": "...", ... }
    }
  ]
}
```

The `remediation_embedding` (768 floats) is stripped from all control objects before writing.

## Correlation engine

The Cypher query uses `OPTIONAL MATCH` so that MITRE and vendor gates degrade gracefully:

- A control with a matching MITRE technique gets a **+0.3 boost**.
- A control from a matching vendor gets a **+0.2 boost**.
- Controls that match neither still appear (ranked by vector similarity alone), ensuring the pipeline never returns empty when relevant controls exist.

Vendor matching uses both exact and `CONTAINS`-based partial matching, so "windows" in the tech stack matches both "Windows" and "Windows Server" vendor nodes. `NIST SP 800-53` is included in the default tech stack so framework-level controls are always considered.

After Cypher retrieval, a lightweight keyword-overlap reranker penalizes candidates whose remediation text shares no meaningful tokens with the finding's technical summary, pushing irrelevant noise down the ranking.

## Graph model

```text
(:Vendor)-[:PROVIDES]->(:Control)-[:MITIGATES]->(:Mitre)
```

- **Vector index:** `control_remediation_vector` on `Control.remediation_embedding` (**768** dimensions, cosine) — `gemini-embedding-001` with `output_dimensionality=768`.

## Data directories

| Path | Role |
|------|------|
| `data/raw/RAG_Corpus` | Default **`RAG_CORPUS_DIR`** for PDF ingest (configurable; see [`config.py`](config.py)) |
| `data/corpus/` | Typical team layout for MITRE STIX, NIST JSON, and CIS/hardening PDFs; use **`--corpus data/corpus`** or `RAG_CORPUS_DIR=data/corpus` to ingest from here |
| `data/mapped/*.json` | Section 2 output (`technical_summary`, `mitre_mapping.mitre_ids`) |
| `data/correlate/*.json` | Section 3 output (correlated findings with top-N candidates) |
| `data/logs/` | Ingestion progress logs (PDF + OSCAL) |

## Tests

From repo root:

```bash
python -m pytest tests/section3 -v
```

Covers progress log resume, `merge_security_control` (mocked Neo4j), composite-scored Cypher structure, query text reformulation, keyword reranker, enriched JSON parsing, candidate serialization, and index-name validation (no live Neo4j or Gemini required).
