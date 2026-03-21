# Section 3 — Hybrid GraphRAG (Gemini + Neo4j)

Ingest hardening guidance from PDFs into a Neo4j graph, then correlate Section 2 **mapped** findings (`data/mapped`) using a **single native Cypher** three-way filter (MITRE + tech stack + vector similarity).

## Prerequisites

1. **Environment** — use the repo-root `.env` you already have; ensure `GOOGLE_API_KEY` is set for Gemini. For Neo4j and paths, merge any missing keys from `.env.example` (Section 3 block). **Embeddings** use the Gemini API model **`gemini-embedding-001`** at **768** dimensions via [`embeddings_gemini.py`](embeddings_gemini.py) (`google.genai.Client.embed_content`). This avoids 404s from `langchain_google_genai.GoogleGenerativeAIEmbeddings` with legacy model ids on the v1beta `embedContent` route. **Chat** extraction still uses [`ChatGoogleGenerativeAI`](llm.py) from `langchain-google-genai`.
2. **Neo4j 5.13+** — vector indexes required. From repo root:

   ```bash
   docker compose up -d
   ```

   Default Bolt: `bolt://localhost:7687`, user `neo4j`, password `changeme` (match `NEO4J_PASSWORD` in `.env`).

3. **Dependencies** — single install from the project [`requirements.txt`](../../requirements.txt) (Section 3 packages are listed there **without** version pins so pip can add them without clobbering your existing Section 1 & 2 versions when possible):

   ```bash
   pip install -r requirements.txt
   ```

## Commands

Run from the **repository root** (`LastMile-Sec`), with `PYTHONPATH` including the project (running `python -m` below adds the cwd automatically on Windows if you `cd` to the repo).

**Apply schema + ingest PDFs** (first run applies constraints and the 768-d vector index from `graph/schema.cypher`):

```bash
python -m src.section3_rag_correlation.cli.ingest
```

Options:

- `--corpus PATH` — override `RAG_CORPUS_DIR` (default `data/raw/RAG_Corpus`).
- `--no-schema` — skip applying `schema.cypher` (use if schema already applied).
- `--limit-pdfs N` / `--limit-batches N` — smoke-test without full corpus.

Progress / resume: `data/logs/processed_pages.log` (JSON lines per batch).

**Ingest NIST OSCAL JSON** (deterministic parse; no LLM extraction). Uses padded join keys + MITRE mapping file, stores `control_id` as `NIST-AC-01` style and `vendor_product` as `NIST SP 800-53`. Progress / resume: `data/logs/processed_oscal_controls.log`.

```bash
python -m src.section3_rag_correlation.cli.ingest_oscal --oscal-catalog "data/raw/RAG_Corpus/NIST_SP-800-53_rev5_catalog.json" --attack-mapping "data/raw/RAG_Corpus/nist_800_53-rev5_attack-16.1-enterprise_json.json"
```

Options:

- `--attack-mapping PATH` — optional; omit to load controls without MITRE edges from this file.
- `--no-schema` — skip applying `schema.cypher`.
- `--limit-controls N` — merge at most N controls (smoke test).
- `--log PATH` — override progress log (default `data/logs/processed_oscal_controls.log`).

**Correlate** enriched JSON (default directory `data/mapped`). Injects `metadata.rag_correlation` (similarity, vendor name, best control without `remediation_embedding`) into each correlatable finding and writes full packets to **`data/correlate`** as `{original_stem}_correlated.json` (override with `CORRELATED_JSON_DIR`). One status line per finding on stdout.

```bash
python -m src.section3_rag_correlation.cli.correlate
```

Examples:

```bash
python -m src.section3_rag_correlation.cli.correlate --json "data/mapped/your_mapped.json" --max-findings 3
python -m src.section3_rag_correlation.cli.correlate --tech-stack "Windows Server,Meraki MS"
```

## Graph model

```text
(:Vendor)-[:PROVIDES]->(:Control)-[:MITIGATES]->(:Mitre)
```

- **Vector index:** `control_remediation_vector` on `Control.remediation_embedding` (**768** dimensions, cosine) — `gemini-embedding-001` with `output_dimensionality=768`.

## Data directories

| Path | Role |
|------|------|
| `data/raw/RAG_Corpus` | PDF corpus for ingestion |
| `data/mapped/*.json` | Section 2 output (`technical_summary`, `mitre_mapping.mitre_ids`) |
| `data/processed` | Section 1 only — **not** used for correlation |

## Tests

From repo root (PowerShell: `$env:PYTHONPATH="."`; bash: `export PYTHONPATH=.`):

```bash
python -m pytest tests/section3 -v
```

Covers progress log resume, `merge_security_control` (mocked Neo4j), unified correlation Cypher, enriched JSON parsing, and index-name validation (no live Neo4j or Gemini required).
