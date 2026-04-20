# LastMile-Sec

**Automated Last-Mile Security Remediation Pipeline**

Transform vulnerability reports into actionable, environment-specific remediation steps that L1/L2 engineers can implement.

## Problem

Translating vulnerability/penetration test reports into concrete hardening steps requires expensive senior engineers with cross-domain expertise. This is an industry-wide bottleneck.

## Solution

A 4-stage AI pipeline that automates the "last mile" of security remediation:

| Section | Description | Status |
|---------|-------------|--------|
| **1. Ingestion** | Parse PDFs, CSV, PCAP → Normalized JSON | Complete |
| **2. Reporter & Mapper** | Summarize events (Gemini) → Map to MITRE ATT&CK IDs (Mistral LoRA + Actian VectorAI RAG) | Complete |
| **3. Correlation + RAG** | Ingest hardening docs into Neo4j graph → Composite-scored correlation (MITRE + vendor + vector similarity) → Top-N remediation candidates per finding | Complete |
| **4. Remediation + Self-RAG** | LLM-generated vendor-tailored remediation with Self-RAG hallucination verification | Complete |

## Setup

Use **Python 3.12 or 3.11 (64-bit)**. **Python 3.14** often has **no PyTorch CUDA wheels** on Windows, so `pip install torch` from the CUDA index fails with `No matching distribution found`.

```powershell
# Navigate to project directory
cd C:\Users\WillYoung\Downloads\CSC699\Project\LastMile-Sec

# Create virtual environment (example: Python 3.12 from the Store / python.org)
py -3.12 -m venv venv

# Activate (Windows PowerShell)
.\venv\Scripts\activate

python -m pip install -U pip
```

**PyTorch (CUDA) for Section 2 local mapper** — install the CUDA build **before** or **after** `requirements.txt`, but **re-run this** if a later `pip install` replaces your build with `+cpu`:

```powershell
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
```

(Use the exact [PyTorch install command](https://pytorch.org/get-started/locally/) for your OS if the CUDA line differs.)

**Actian VectorAI client (`actiancortex`)** — the package **`actiancortex`** is **not** on the public PyPI index. Install the **`.whl`** supplied by Actian (or your team). Example location used on this project machine:

`C:\Users\WillYoung\Downloads\actiancortex-0.1.0b1-py3-none-any.whl`

```powershell
pip install "C:\Users\WillYoung\Downloads\actiancortex-0.1.0b1-py3-none-any.whl"
pip install -r requirements.txt
```

Adjust the path if you store the wheel elsewhere.

If `requirements.txt` fails on `actiancortex`, install the wheel first, then run `pip install -r requirements.txt` again (or temporarily comment that line out).

**Verify GPU + client:**

```powershell
python scripts/check_torch_cuda.py
python -c "from cortex import CortexClient; print('actiancortex OK')"
```

Expect `torch.__version__` to show **`+cu124`** (or similar) and `torch.cuda.is_available(): True`. Pip may warn about `protobuf`/`google-*` version overlap after installing `actiancortex`; if Gemini calls fail, upgrade Google client packages or align `protobuf` per their docs.

**Optional:** set `HF_TOKEN` if Hugging Face downloads models slowly or rate-limit.

### Neo4j (Section 3 — GraphRAG)

Section 3 requires a Neo4j 5.13+ instance with native vector index support. If you have a **`docker-compose.yml`** (often maintained locally; see [Local-only configuration files](#local-only-configuration-files)), start the bundled container:

```powershell
docker compose up -d
```

That typically starts a Neo4j Community 5.23 container with the browser at [http://localhost:7474](http://localhost:7474) and Bolt at `bolt://localhost:7687`. Default credentials are `neo4j` / `changeme` (set `NEO4J_PASSWORD` in `.env` to match).

### Environment Variables

Create a **`.env`** file in the repo root (use a team-supplied **`.env.example`** as a template if available) and fill in the required keys:

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_API_KEY` | Yes | Gemini API key (extraction + embeddings) |
| `NEO4J_PASSWORD` | Yes | Must match the `docker-compose.yml` auth (default `changeme`) |
| `NEO4J_URI` | No | Override Bolt URI (default `bolt://localhost:7687`) |
| `GLOBAL_TECH_STACK` | No | Comma-separated vendor names for correlation (default `Windows Server,Meraki MS,M365,NIST SP 800-53`) |

### Local-only configuration files

This repository’s [`.gitignore`](.gitignore) excludes **`docker-compose.yml`** and **`.env.example`**, so a fresh `git clone` may not contain them. Add your own Neo4j Compose file and environment template (or obtain copies from your team), then create **`.env`** with the keys from the table above. Without a Compose file, run Neo4j 5.13+ another way and point `NEO4J_URI` / `NEO4J_PASSWORD` at it.

## Project Structure

```
LastMile-Sec/
├── run.py                             # Section 1 CLI (parse files)
├── run_pipeline.py                    # Sections 1–4 orchestrator (subprocess; Neo4j pre-populated for S3)
├── run_reporter.py                    # Section 2 Reporter-only CLI
├── run_section2.py                    # Section 2 full pipeline CLI
├── docker-compose.yml                 # Neo4j 5.23 container (often not committed; see above)
├── requirements.txt
├── _requirements_no_actian.txt        # Optional: dependencies without actiancortex line
├── scripts/
│   ├── check_json.py
│   ├── check_torch_cuda.py            # Verify PyTorch CUDA build
│   ├── check_vector_db.py             # VectorAI collection readiness
│   ├── compare_parsers.py
│   ├── regenerate_json.py
│   ├── review_mapped.py               # Review mapped MITRE output
│   └── seed_vector_db.py              # Seed ATT&CK + mapped findings into VectorAI
├── lastmile-ui/                       # Next.js UI (MITRE matrix, remediation, graph demos)
├── vde_storage/                       # Local Actian Vector DB persisted state (when used)
├── src/
│   ├── section1_ingestion/
│   │   ├── schemas.py                 # Pydantic data models
│   │   ├── normalizer.py              # Orchestrator
│   │   └── parsers/
│   │       ├── csv_parser.py          # CSV vulnerability reports
│   │       ├── pcap_parser.py         # Network packet captures
│   │       ├── pdf_parser.py          # PDF (regex-based)
│   │       └── pdf_parser_langextract.py  # PDF (LLM-powered)
│   ├── section2_report_map/
│   │   ├── reporter.py                # Reporter Agent (Gemini summaries)
│   │   ├── mapper.py                  # Mapper Agent (Mistral LoRA + VectorAI RAG)
│   │   ├── validation.py             # MITRE ID validation gates + fallback policy
│   │   ├── config.py                  # API keys, models, thresholds
│   │   ├── prompts.py                 # LLM prompt templates
│   │   ├── SECTION2_README.md         # Extended Section 2 reference
│   │   └── FineTuningNotebook/        # LoRA training notebooks
│   ├── section3_rag_correlation/
│   │   ├── cli/
│   │   │   ├── ingest.py              # PDF → Neo4j ingestion CLI
│   │   │   ├── ingest_oscal.py        # NIST OSCAL JSON → Neo4j ingestion CLI
│   │   │   └── correlate.py           # Three-way correlation CLI
│   │   ├── correlation/
│   │   │   ├── enriched_input.py      # Load Section 2 mapped JSON findings
│   │   │   └── three_way_filter.py    # Composite-scored Cypher + reranker
│   │   ├── graph/
│   │   │   ├── neo4j_client.py        # Neo4j driver + schema application
│   │   │   ├── merge_controls.py      # Idempotent MERGE for controls
│   │   │   └── schema.cypher          # Constraints + 768-d vector index
│   │   ├── ingestion/
│   │   │   ├── extract.py             # Gemini 2.5 Flash structured extraction
│   │   │   ├── pdf_batches.py         # PDF → multi-page batch loader
│   │   │   ├── oscal_nist.py          # NIST OSCAL JSON parser
│   │   │   └── progress.py            # Resume logging (PDF + OSCAL)
│   │   ├── config.py                  # Section 3 configuration
│   │   ├── embeddings_gemini.py       # gemini-embedding-001 (768-d)
│   │   ├── llm.py                     # Gemini chat + embedding singletons
│   │   └── schemas.py                 # SecurityControl Pydantic model
│   └── section4_remediation/
│       ├── cli/
│       │   └── remediate.py           # Section 4 CLI (generate + verify)
│       ├── config.py                  # Section 4 configuration + Self-RAG thresholds
│       ├── generator.py               # Gemini structured remediation generation
│       ├── prompts.py                 # Prompt templates (generation, grounding judge, retry)
│       ├── schemas.py                 # RemediationOutput, VerificationResult models
│       ├── retrieval_policy.py        # When to enable Google Search grounding
│       ├── grounding_serialization.py # Grounding blobs for JSON + Self-RAG
│       └── selfrag.py                 # Self-RAG verifier (4 checks) + retry loop orchestration
├── tests/
│   ├── manual_integration_test.py     # End-to-end pipeline test (mocked)
│   ├── section3/                      # Section 3 unit tests (no live Neo4j)
│   ├── section4/                      # Section 4 unit tests (mocked LLM)
│   └── test_*.py                      # Sections 1–2, parsers, validation, VectorAI, etc.
├── data/
│   ├── corpus/                        # MITRE STIX, NIST JSON, CIS/hardening PDFs (typical layout)
│   ├── raw/                           # Input reports (contents often gitignored)
│   │   └── RAG_Corpus/                # Alternate: PDF + JSON corpus (Section 3 default path)
│   ├── processed/                     # Section 1 output (normalized JSON)
│   ├── mapped/                        # Section 2 output (enriched with MITRE IDs)
│   ├── correlate/                     # Section 3 output (*_correlated.json)
│   ├── remediated/                    # Section 4 output (*_remediated_YYYYMMDD_HHMMSS.json)
│   ├── cache/                         # Reporter summary cache
│   └── logs/                          # Ingestion progress logs
└── Weekly Review/                     # Project documentation
```

**Corpus paths:** Section 3 PDF ingest defaults to **`RAG_CORPUS_DIR=data/raw/RAG_Corpus`** (see [`src/section3_rag_correlation/config.py`](src/section3_rag_correlation/config.py)). This repo often keeps MITRE/NIST/CIS assets under **`data/corpus/`** (e.g. `enterprise-attack-18.1.json` for seeding). To ingest those PDFs, set `RAG_CORPUS_DIR` to `data/corpus` or pass **`--corpus`** to the ingest CLI. Vector DB seeding examples use `data/corpus/enterprise-attack-18.1.json` for the ATT&CK bundle.

## Usage

### Full pipeline (Sections 1–4)

Runs [`run_pipeline.py`](run_pipeline.py): Section 1 with **LangExtract** for PDFs, Section 2 (Reporter + Mapper), Section 3 **correlate only** (assumes Neo4j is **already seeded**), Section 4 **remediate** with LLM-as-judge enabled.

Requires `GOOGLE_API_KEY`, Neo4j reachable, Vector DB seeded for Section 2 (`scripts/seed_vector_db.py` / `check_vector_db.py`) as needed.

```powershell
.\venv\Scripts\activate
python run_pipeline.py "data/raw/your_report.pdf"
python run_pipeline.py "data/raw/your_report.pdf" --routing-mode local --max-findings 5
```

### Section 1: Parse Raw Files

```powershell
.\venv\Scripts\activate

python run.py "data/raw/your_report.csv"
python run.py "data/raw/your_capture.pcap"
python run.py "data/raw/your_report.pdf"
```

Output is saved to `data/processed/` as normalized JSON.

**PDF + LangExtract** (`--pdf-parser langextract`): extraction calls Gemini via LangExtract. Transient **503/429** / **UNAVAILABLE** responses are retried with exponential backoff; cumulative **sleep** between attempts is capped at **60** seconds by default (`LANGEXTRACT_GEMINI_MAX_BACKOFF_SECONDS`). If extraction still fails or returns no findings, the parser falls back to the regex PDF parser.

### Section 2: Reporter + Mapper Pipeline

```powershell
# Set Gemini API key
$env:GOOGLE_API_KEY = "your-key"

# Run full pipeline (Reporter -> Mapper) on a Section 1 output file
python run_section2.py "data/processed/report.json"

# Limit findings for testing
python run_section2.py "data/processed/report.json" --max-findings 5

# Output saved to data/mapped/ with MITRE ATT&CK IDs per finding
```

### Section 2 Vector DB Seeding + Health Check

```powershell
# Seed VectorAI collection from ATT&CK corpus + local mapped findings
python scripts/seed_vector_db.py --attack-corpus data/corpus/enterprise-attack-18.1.json --mapped-dir data/mapped

# Validate collection readiness for strict RAG mode
python scripts/check_vector_db.py --json
```

### Section 3: Graph RAG Correlation

Requires Neo4j running (`docker compose up -d`) and `GOOGLE_API_KEY` set.

```powershell
# 1. Ingest PDF hardening guides into Neo4j
python -m src.section3_rag_correlation.cli.ingest

# 2. Ingest NIST OSCAL JSON (deterministic, no LLM)
# Catalog: use data/corpus if you keep NIST JSON alongside other corpus files.
# Attack mapping: download the NIST↔ATT&CK mapping JSON (e.g. from NIST/OSCAL releases) if not present locally.
python -m src.section3_rag_correlation.cli.ingest_oscal `
  --oscal-catalog "data/corpus/NIST_SP-800-53_rev5_catalog.json" `
  --attack-mapping "data/corpus/nist_800_53-rev5_attack-16.1-enterprise_json.json"

# 3. Correlate Section 2 findings against the graph
python -m src.section3_rag_correlation.cli.correlate

# Single file with limited findings
python -m src.section3_rag_correlation.cli.correlate --json "data/mapped/your_mapped.json" --max-findings 5

# Override tech stack
python -m src.section3_rag_correlation.cli.correlate --tech-stack "Windows Server,Ubuntu Linux,NIST SP 800-53"
```

Correlated output is written to `data/correlate/` with a `_correlated.json` suffix. Each finding's `metadata.rag_correlation` block contains the top-N ranked candidates with composite scores, MITRE/vendor match flags, and sanitized control details.

See [`src/section3_rag_correlation/README.md`](src/section3_rag_correlation/README.md) for the full Section 3 reference.

### Section 4: Remediation Generation + Self-RAG Verification

Requires `GOOGLE_API_KEY` set. Reads `_correlated.json` from Section 3 and produces timestamped `_remediated_YYYYMMDD_HHMMSS.json` files with vendor-tailored L1/L2 remediation steps.

```powershell
# Generate remediation for all correlated findings
python -m src.section4_remediation.cli.remediate

# Single file with limited findings
python -m src.section4_remediation.cli.remediate --json "data/correlate/your_correlated.json" --max-findings 5

# Override tech stack
python -m src.section4_remediation.cli.remediate --tech-stack "Windows Server,Ubuntu Linux,NIST SP 800-53"

# Skip LLM-as-judge grounding (faster, heuristic-only verification)
python -m src.section4_remediation.cli.remediate --skip-llm-judge

# Optional: Gemini Google Search grounding for thin-corpus vendors (Meraki, Ubiquiti, etc.)
python -m src.section4_remediation.cli.remediate --enable-search-augmentation
```

Output is written to `data/remediated/` with a timestamped `_remediated_YYYYMMDD_HHMMSS.json` suffix (each run produces a unique file). Each finding's `metadata.remediation` block contains:

- **steps** -- ordered remediation steps, each with `step_type` (`investigation`/`hardening`/`monitoring`), `ui_breadcrumb` for GUI navigation, ordered `substeps` for click-by-click walkthroughs, title, command/action, explanation, and vendor
- **executive_summary** -- high-level summary of the remediation approach
- **limitations** -- honest disclosure of any information gaps
- **priority** -- critical/high/medium/low
- **estimated_effort** -- time estimate for the engineer
- **prerequisites** -- access or tools needed
- **verification_procedure** -- how to confirm the fix
- **source_control_ids** -- traceability back to the ingested controls
- **provenance** -- `graph_only` or `graph_plus_search` mode, trigger reason, grounding metadata
- **selfrag_verification** -- grounding, relevance, completeness, and substep quality scores with pass/fail status

The Self-RAG verification loop checks each generated remediation for:
1. **Grounding** -- steps must be supported by the source control text (token overlap + LLM judge)
2. **Relevance** -- steps must address the finding's technical summary and MITRE techniques
3. **Completeness** -- steps must reference the top correlated controls
4. **Substep Quality** -- each step must have >= 3 substeps, GUI steps must have a `ui_breadcrumb`, and at least one substep should include a confirmation hint

If verification fails, the generator retries with augmented feedback that reinforces substep/breadcrumb requirements (up to `SELFRAG_MAX_RETRIES`, default 2).

See [`src/section4_remediation/README.md`](src/section4_remediation/README.md) for the full Section 4 reference.

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SELFRAG_GROUNDING_THRESHOLD` | `0.7` | Minimum grounding score to pass |
| `SELFRAG_RELEVANCE_THRESHOLD` | `0.5` | Minimum relevance score to pass |
| `SELFRAG_COMPLETENESS_THRESHOLD` | `0.5` | Minimum completeness score to pass |
| `SELFRAG_SUBSTEP_QUALITY_THRESHOLD` | `0.7` | Minimum substep quality score to pass |
| `SELFRAG_MAX_RETRIES` | `2` | Max retry attempts on verification failure |
| `REMEDIATION_LLM_TEMPERATURE` | `0.2` | LLM temperature for generation |
| `REMEDIATED_JSON_DIR` | `data/remediated` | Output directory |

### Run Tests

```powershell
.\venv\Scripts\activate
python -m pytest tests/ -v
python tests/manual_integration_test.py
```

### Using in Python Code

```python
from src.section1_ingestion import Normalizer

# Create normalizer with output directory
normalizer = Normalizer(output_dir="data/processed")

# Parse and save a file
packet, output_path = normalizer.ingest_and_save("data/raw/report.csv")

# View results
print(f"Findings: {packet.finding_count}")
print(f"Critical: {packet.critical_count}")
print(f"Saved to: {output_path}")
```

### PDF Parser Options

| Parser | Speed | Accuracy | Requirements |
|--------|-------|----------|--------------|
| **Regex** (default) | Fast | Basic | None (offline) |
| **LangExtract** | Slower | Better for varied formats | `GOOGLE_API_KEY` |

```python
# Use LangExtract for better PDF parsing (requires API key)
# Set environment variable: $env:GOOGLE_API_KEY = "your-key"
normalizer = Normalizer(pdf_parser="langextract")
```

## Supported File Types

| Format | Parser | Status |
|--------|--------|--------|
| CSV | csv_parser | Works great |
| PCAP | pcap_parser | Works |
| PDF | pdf_parser | Basic (use LangExtract for better results) |

## License

MIT License - See LICENSE file
