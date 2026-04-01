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
| **4. Output** | Step-by-step instructions for L1/L2 engineers | Planned |

## Setup

```powershell
# Navigate to project directory
cd C:\Users\WillYoung\Downloads\CSC699\Project\LastMile-Sec

# Create virtual environment
python -m venv venv

# Activate (Windows PowerShell)
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Neo4j (Section 3 — GraphRAG)

Section 3 requires a Neo4j 5.13+ instance with native vector index support. A pre-configured container is provided via Docker Compose:

```powershell
docker compose up -d
```

This starts a Neo4j Community 5.23 container with the browser at [http://localhost:7474](http://localhost:7474) and Bolt at `bolt://localhost:7687`. Default credentials are `neo4j` / `changeme` (set `NEO4J_PASSWORD` in `.env` to match).

### Environment Variables

Copy `.env.example` to `.env` and fill in the required keys:

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_API_KEY` | Yes | Gemini API key (extraction + embeddings) |
| `NEO4J_PASSWORD` | Yes | Must match the `docker-compose.yml` auth (default `changeme`) |
| `NEO4J_URI` | No | Override Bolt URI (default `bolt://localhost:7687`) |
| `GLOBAL_TECH_STACK` | No | Comma-separated vendor names for correlation (default `Windows Server,Meraki MS,M365,NIST SP 800-53`) |

## Project Structure

```
LastMile-Sec/
├── run.py                             # Section 1 CLI (parse files)
├── run_reporter.py                    # Section 2 Reporter-only CLI
├── run_section2.py                    # Section 2 full pipeline CLI
├── docker-compose.yml                 # Neo4j 5.23 container for Section 3
├── requirements.txt
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
│   │   ├── config.py                  # API keys, models, thresholds
│   │   └── prompts.py                 # LLM prompt templates
│   └── section3_rag_correlation/
│       ├── cli/
│       │   ├── ingest.py              # PDF → Neo4j ingestion CLI
│       │   ├── ingest_oscal.py        # NIST OSCAL JSON → Neo4j ingestion CLI
│       │   └── correlate.py           # Three-way correlation CLI
│       ├── correlation/
│       │   ├── enriched_input.py      # Load Section 2 mapped JSON findings
│       │   └── three_way_filter.py    # Composite-scored Cypher + reranker
│       ├── graph/
│       │   ├── neo4j_client.py        # Neo4j driver + schema application
│       │   ├── merge_controls.py      # Idempotent MERGE for controls
│       │   └── schema.cypher          # Constraints + 768-d vector index
│       ├── ingestion/
│       │   ├── extract.py             # Gemini 2.5 Flash structured extraction
│       │   ├── pdf_batches.py         # PDF → multi-page batch loader
│       │   ├── oscal_nist.py          # NIST OSCAL JSON parser
│       │   └── progress.py            # Resume logging (PDF + OSCAL)
│       ├── config.py                  # Section 3 configuration
│       ├── embeddings_gemini.py       # gemini-embedding-001 (768-d)
│       ├── llm.py                     # Gemini chat + embedding singletons
│       └── schemas.py                 # SecurityControl Pydantic model
├── tests/
│   ├── test_section1.py               # Section 1 unit tests
│   ├── test_reporter.py               # Reporter unit tests
│   ├── test_mapper.py                 # Mapper unit tests
│   ├── manual_integration_test.py     # End-to-end pipeline test
│   └── section3/                      # Section 3 unit tests (40 tests, no live Neo4j)
├── data/
│   ├── raw/                           # Input files (not committed)
│   │   └── RAG_Corpus/                # PDF + NIST JSON corpus for Section 3
│   ├── processed/                     # Section 1 output (normalized JSON)
│   ├── mapped/                        # Section 2 output (enriched with MITRE IDs)
│   ├── correlate/                     # Section 3 output (*_correlated.json)
│   ├── cache/                         # Reporter summary cache
│   └── logs/                          # Ingestion progress logs
└── Weekly Review/                     # Project documentation
```

## Usage

### Section 1: Parse Raw Files

```powershell
.\venv\Scripts\activate

python run.py "data/raw/your_report.csv"
python run.py "data/raw/your_capture.pcap"
python run.py "data/raw/your_report.pdf"
```

Output is saved to `data/processed/` as normalized JSON.

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
python -m src.section3_rag_correlation.cli.ingest_oscal `
  --oscal-catalog "data/raw/RAG_Corpus/NIST_SP-800-53_rev5_catalog.json" `
  --attack-mapping "data/raw/RAG_Corpus/nist_800_53-rev5_attack-16.1-enterprise_json.json"

# 3. Correlate Section 2 findings against the graph
python -m src.section3_rag_correlation.cli.correlate

# Single file with limited findings
python -m src.section3_rag_correlation.cli.correlate --json "data/mapped/your_mapped.json" --max-findings 5

# Override tech stack
python -m src.section3_rag_correlation.cli.correlate --tech-stack "Windows Server,Ubuntu Linux,NIST SP 800-53"
```

Correlated output is written to `data/correlate/` with a `_correlated.json` suffix. Each finding's `metadata.rag_correlation` block contains the top-N ranked candidates with composite scores, MITRE/vendor match flags, and sanitized control details.

See [`src/section3_rag_correlation/README.md`](src/section3_rag_correlation/README.md) for the full Section 3 reference.

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
