# Section 2: Reporter & Mapper

## Overview

Section 2 takes normalized JSON packets from Section 1 (Ingestion) and produces validated MITRE ATT&CK technique IDs for each security finding. It runs as a two-stage pipeline:

1. **Reporter Agent** (Gemini 2.5 Flash) -- generates a concise technical summary sentence per finding
2. **Mapper Agent** (Mistral-7B LoRA + Actian VectorAI RAG) -- maps each summary to MITRE ATT&CK Enterprise technique IDs

The final deliverable from Section 2 is an enriched JSON packet where every finding carries both a `technical_summary` and a `mitre_mapping` with validated technique IDs.

## Pipeline Architecture

```
Section 1 JSON (data/processed/*.json)
    |
    v
+----------------------------------------------+
|         run_section2.py (unified CLI)        |
+----------------------------------------------+
    |
    |  Step 1
    v
+----------------------------------------------+
|           Reporter Agent (Gemini)            |
|                                              |
|  For each finding:                           |
|    - Extract title, CVEs, services, ports    |
|    - Build evidence-based prompt             |
|    - Call Gemini 2.5 Flash (thinking off)    |
|    - Validate: 5-80 words, single sentence   |
|    - Cache valid summaries (SHA-256 keyed)   |
|    - Fallback to deterministic summary       |
|      if LLM output is unusable              |
|                                              |
|  Output: technical_summary in metadata       |
+----------------------------------------------+
    |
    |  Step 2
    v
+----------------------------------------------+
|          Mapper Agent (Local LoRA)           |
|                                              |
|  For each summarized finding:                |
|    1. Embed summary (all-MiniLM-L6-v2)       |
|    2. Query Actian VectorAI for top-k        |
|       similar historical examples            |
|    3. Build prompt with RAG context          |
|    4. Run local Mistral-7B LoRA adapter      |
|       (4-bit quantized, PEFT)                |
|    5. Extract technique IDs from output      |
|    6. Validate against Enterprise ATT&CK     |
|       v18.1 registry (200+ root IDs)         |
|                                              |
|  Output: mitre_mapping in metadata           |
|    - mitre_ids: ["T1190", "T1059.004"]       |
|    - validation_passed: true/false           |
|    - routing_mode: "local"                   |
|    - mapping_agent: "Mistral-7B-LoRA"        |
|    - db_context: "Actian-VectorAI"           |
|    - framework: "enterprise 18.1"            |
|    - retrieved_examples: 2                   |
|    - raw_model_output: "..."                 |
|    - mapped_at: "2026-03-04 16:52:59"        |
+----------------------------------------------+
    |
    v
Final enriched JSON (data/mapped/*.json)
```

## Components

### `reporter.py` -- Reporter Agent

Generates one-sentence technical summaries via Gemini 2.5 Flash.

| Method | Description |
|--------|-------------|
| `generate_summary(finding)` | Summarize a single finding |
| `process_packet(packet, max_findings)` | Batch-process all findings in a packet |
| `process_json_file(path)` | Load a Section 1 JSON and process it |
| `save_enriched_packet(packet, dir)` | Save the Reporter-enriched output |

Summary validation rejects scanner boilerplate and multi-sentence output. When the LLM response is unusable, a deterministic fallback summary is built from the finding's title, CVEs, and services.

### `mapper.py` -- Mapper Agent

Maps each Reporter-enriched finding to MITRE ATT&CK Enterprise techniques using a hybrid RAG + local LLM approach.

| Method | Description |
|--------|-------------|
| `map_finding(finding)` | Map a single finding to ATT&CK IDs |
| `process_packet(packet, max_findings)` | Batch-map all findings in a packet |
| `save_mapped_packet(packet, dir)` | Save the fully mapped output |

The Mapper supports two routing modes:

| Mode | Model | Use Case |
|------|-------|----------|
| **local** (default) | Mistral-7B-Instruct-v0.2 + LoRA adapter | Production -- runs on GPU, no API cost |
| **cloud** | Gemini 2.5 Flash | Fallback when GPU is unavailable |

> **Note on Model Verbosity:** The local Mistral-7B model often generates "Chain-of-Thought" reasoning (e.g., *"Based on the RDP port, I've identified..."*). The Mapper includes a post-processing extraction layer that filters this conversational "chatter" to ensure only valid `Txxxx` and `Txxxx.xxx` IDs populate the final `mitre_ids` list. This
COT is recorded in the `raw_model_output` metadata category for auditability.

### `config.py` -- Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| `GEMINI_MODEL` | gemini-2.5-flash | Reporter model |
| `LOCAL_BASE_MODEL` | mistralai/Mistral-7B-Instruct-v0.2 | Mapper base |
| `LOCAL_ADAPTER_PATH` | C:\Users\WillYoung\Downloads\CSC699\final_adapter | Trained LoRA weights |
| `EMBEDDING_MODEL` | sentence-transformers/all-MiniLM-L6-v2 | For VectorAI queries |
| `VECTOR_DB_ADDRESS` | localhost:50051 | Actian VectorAI gRPC |
| `VECTOR_DB_COLLECTION` | mitre_v18_1 | Historical examples |
| `ATTACK_MAPPER_REQUIRE_RAG` | true | Fail fast if VectorAI collection is not ready |
| `ATTACK_MAPPER_MIN_COLLECTION_VECTORS` | 1 | Minimum vectors required before mapping |
| `ATTACK_MAPPER_EXPECTED_EMBEDDING_DIM` | 384 | Probe vector dimensionality for readiness |
| `ATTACK_VERSION` | 18.1 | Enterprise framework version |
| `ROUTING_MODE` | local | Default routing for Mapper |

### `prompts.py` -- Prompt Templates

| Prompt | Used By | Purpose |
|--------|---------|---------|
| `SummaryPrompts.SYSTEM_PROMPT` | Reporter | Constrains Gemini to produce a single technical sentence |
| `SummaryPrompts.USER_PROMPT_TEMPLATE` | Reporter | Injects finding evidence into the prompt |
| `AttackMapperPrompts.SYSTEM_PROMPT` | Mapper (cloud) | Structured JSON output schema for ATT&CK mapping |
| `AttackMapperPrompts.CLOUD_RAG_USER_PROMPT_TEMPLATE` | Mapper (cloud) | Includes RAG context + finding details |
| `AttackMapperPrompts.LOCAL_USER_PROMPT_TEMPLATE` | Mapper (local) | Mistral instruction format with RAG context |

## Usage

### Full Pipeline (Reporter + Mapper)

```powershell
# Set API key
$env:GOOGLE_API_KEY = "your-key"

# Run on a single file (local Mistral LoRA, default)
python run_section2.py "data/processed/report.json"

# Limit to 5 findings for testing
python run_section2.py "data/processed/report.json" --max-findings 5

# Use cloud routing instead of local
python run_section2.py "data/processed/report.json" --routing-mode cloud

# Batch process a directory
python run_section2.py --batch data/processed --output-dir data/mapped
```

### Vector DB Readiness + Seeding

```powershell
# Optional strictness overrides (strict by default)
$env:ATTACK_MAPPER_REQUIRE_RAG = "true"
$env:ATTACK_MAPPER_VECTOR_DB_ADDRESS = "localhost:50051"
$env:ATTACK_MAPPER_VECTOR_DB_COLLECTION = "mitre_v18_1"

# Seed corpus + local mapped findings into VectorAI
python scripts/seed_vector_db.py --attack-corpus data/corpus/enterprise-attack-18.1.json --mapped-dir data/mapped

# Check readiness (exit code 0 = ready, 2 = not ready)
python scripts/check_vector_db.py --json
```

### Seed Data Source (MITRE ATT&CK v18.1)

The Vector DB is seeded from the MITRE ATT&CK Enterprise STIX bundle (v18.1):

- Local canonical file: `data/corpus/enterprise-attack-18.1.json`
- Upstream source: https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack-18.1.json

`seed_vector_db.py` uses this dataset by:

1. Reading STIX `objects` and keeping only `attack-pattern` entries.
2. Skipping revoked/deprecated techniques (`revoked=true` or `x_mitre_deprecated=true`).
3. Extracting ATT&CK IDs from `external_references` where `source_name="mitre-attack"` (e.g., `T1190`, `T1003.001`).
4. Building `technical_summary` from `description` (fallback: `name`) and carrying useful metadata (for example, `x_mitre_platforms`).
5. Merging these corpus rows with validated local rows from `data/mapped/*.json`, then deduplicating.

How this is used at runtime:

- Seed-time: each summary is embedded (`sentence-transformers/all-MiniLM-L6-v2`, 384-dim) and written to collection `mitre_v18_1`.
- Map-time: each finding summary is embedded and searched against `mitre_v18_1` for top-k similar examples.
- Those retrieved examples are injected into the mapper prompt to improve ATT&CK ID selection (`retrieved_examples` in output metadata).

### Reporter Only

```powershell
python run_reporter.py "data/processed/report.json"
python run_reporter.py --batch data/processed --output-dir data/enriched
```

### Run Tests

```powershell
# Unit tests (offline, fast)
python -m pytest tests/test_reporter.py tests/test_reporter_mock.py tests/test_mapper.py -v

# Integration test (offline, mocked clients)
python tests/manual_integration_test.py
```

## Output Format

Each finding in the output JSON contains enriched metadata:

```json
{
  "id": "finding-001",
  "severity": "critical",
  "title": "OpenBSD OpenSSH < 9.3p2 RCE Vulnerability",
  "metadata": {
    "technical_summary": "OpenSSH 7.9 allows remote code execution through forwarded ssh-agent PKCS#11 library abuse via CVE-2023-38408.",
    "summary_source": "llm",
    "summary_model": "gemini-2.5-flash",
    "mitre_mapping": {
      "mitre_ids": ["T1105"],
      "validation_passed": true,
      "routing_mode": "local",
      "mapping_agent": "Mistral-7B-LoRA",
      "db_context": "Actian-VectorAI",
      "framework": "enterprise 18.1",
      "retrieved_examples": 2
    }
  }
}
```

Run-level metadata now includes mapper Vector DB readiness details under:
`metadata.mapper_stats.vector_db_status`.

## Caching

The Reporter caches valid Gemini summaries to avoid redundant API calls.

- **Key**: SHA-256 hash of (prompt version + model + title + description + CVEs + services + ports)
- **Storage**: `data/cache/` as plain text files
- **Invalidation**: Bump `SUMMARY_PROMPT_VERSION` in config when prompts or validation logic change (currently `summary_v3`)

## MITRE Validation

The `MitreValidator` checks every technique ID the Mapper produces against the full MITRE ATT&CK Enterprise v18.1 registry (200+ root technique IDs across all 14 tactics). Sub-techniques like `T1059.004` are accepted if their root ID `T1059` is in the registry.

## File Structure

```
src/section2_report_map/
    __init__.py             # Package exports
    reporter.py             # Reporter Agent (Gemini)
    mapper.py               # Mapper Agent (Mistral LoRA + VectorAI)
    config.py               # All configuration
    prompts.py              # LLM prompt templates

run_section2.py             # Unified CLI (Reporter -> Mapper)
run_reporter.py             # Reporter-only CLI

data/
    processed/              # Section 1 output (input to Section 2)
    mapped/                 # Section 2 output (enriched with MITRE IDs)
    cache/                  # Reporter summary cache

tests/
    test_mapper.py          # Mapper unit tests
    test_reporter.py        # Reporter unit tests
    test_reporter_mock.py   # Reporter cache tests
    manual_integration_test.py  # End-to-end pipeline test (mocked)
```

## Dependencies

| Package | Purpose |
|---------|---------|
| google-genai | Gemini API (Reporter + cloud Mapper) |
| sentence-transformers | Embedding model for VectorAI queries |
| actiancortex | Actian VectorAI client for RAG |
| transformers + peft | Mistral-7B base + LoRA adapter loading |
| bitsandbytes | 4-bit quantization for local inference |
| protobuf >= 6.31.1 | Required by actiancortex (must match gencode version) |
