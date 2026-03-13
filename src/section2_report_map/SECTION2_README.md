# Section 2: Reporter & Mapper

## Overview

Section 2 takes normalized JSON packets from Section 1 (Ingestion) and produces validated MITRE ATT&CK technique IDs for each security finding. It runs as a two-stage pipeline:

1. **Reporter Agent** (Gemini 2.5 Flash) -- generates a concise technical summary sentence per finding
2. **Mapper Agent** (Mistral-7B LoRA v2 + Actian VectorAI RAG) -- maps each summary to MITRE ATT&CK Enterprise technique IDs
3. **Validation Layer** -- three-gate validation pipeline (format, consistency, policy) governs output quality

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
|      if LLM output is unusable               |
|                                              |
|  Output: technical_summary in metadata       |
+----------------------------------------------+
    |
    |  Step 2
    v
+----------------------------------------------+
|          Mapper Agent (Local LoRA v2)        |
|                                              |
|  For each summarized finding:                |
|    1. Embed summary (all-MiniLM-L6-v2)       |
|    2. Query Actian VectorAI for top-k        |
|       similar historical examples            |
|    3. Build RAG-aware prompt with             |
|       ### Reference Examples from Database   |
|    4. Run Mistral-7B LoRA v2 adapter         |
|       (4-bit NF4 quantized, PEFT)            |
|    5. Grammar-constrained decoding:          |
|       - StoppingCriteria halts on ]          |
|       - LogitsProcessor constrains vocab     |
|         to ATT&CK ID characters only         |
|    6. Extract technique IDs (ast.literal_eval|
|       -> JSON -> regex fallback)             |
|    7. Three-gate validation:                 |
|       - Format: well-formed + known ID?      |
|       - Consistency: tactic-summary match    |
|         (advisory, does not block)           |
|       - Policy: max techniques per finding   |
|                                              |
|  Output: mitre_mapping in metadata           |
|    - mitre_ids: ["T1190", "T1059.004"]       |
|    - validation_passed: true/false           |
|    - validation_gates: {format, consistency, |
|        policy}                               |
|    - validation_issues: [...]                |
|    - rejected_ids: [...]                     |
|    - routing_mode: "local"                   |
|    - mapping_agent: "Mistral-7B-LoRA"        |
|    - db_context: "Actian-VectorAI"           |
|    - framework: "enterprise 18.1"            |
|    - retrieved_examples: 2                   |
|    - raw_model_output: "['T1190']"           |
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
| **local** (default) | Mistral-7B-Instruct-v0.1 + LoRA v2 adapter | Production -- runs on GPU, no API cost |
| **cloud** | Gemini 2.5 Flash | Fallback when GPU is unavailable |

#### Decoding Guards

The local Mapper uses two decoding constraints to prevent hallucination:

- **StoppingCriteria** -- halts generation immediately when `]` is decoded, keeping output to ~10 tokens
- **LogitsProcessor** -- constrains the output vocabulary to characters valid in ATT&CK ID lists: `' T 0-9 . , ] \n`

These are implemented in the `_LocalDecodingGuards` class. Combined with `max_new_tokens=50`, the model produces clean `['T1059.001']` output instead of rambling text.

#### Output Extraction

`_extract_technique_ids()` parses model output using a three-tier fallback:

1. `ast.literal_eval` for Python list literals (primary format from LoRA)
2. `json.loads` for JSON arrays
3. Regex `T\d{4}(?:\.\d{3})?` as last resort

### `validation.py` -- Three-Gate Validation Layer

Implements the validation pipeline from the Esposito thesis (Section 4.3):

| Gate | Type | Behavior |
|------|------|----------|
| **Format** | Hard gate | Rejects malformed IDs and IDs not in ATT&CK Enterprise v18.1 |
| **Consistency** | Advisory | Warns when a technique's tactic family has no keyword overlap with the summary. Does not block validation. |
| **Policy** | Hard gate | Drops excess IDs when count exceeds `MAX_TECHNIQUES_PER_FINDING` (default: 5) |

The `MappingValidator` class is injected into the `Mapper` and runs after ID extraction. Results include `validation_gates`, `validation_issues`, and `rejected_ids` in the output metadata.

### `config.py` -- Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| `GEMINI_MODEL` | gemini-2.5-flash | Reporter model |
| `LOCAL_BASE_MODEL` | mistralai/Mistral-7B-Instruct-v0.1 | Must match training base model |
| `LOCAL_ADAPTER_PATH` | final_adapter_v2 | RAG-aware LoRA weights |
| `LOCAL_MAX_NEW_TOKENS` | 50 | Hard upper bound on generation |
| `EMBEDDING_MODEL` | sentence-transformers/all-MiniLM-L6-v2 | For VectorAI queries |
| `VECTOR_DB_ADDRESS` | localhost:50051 | Actian VectorAI gRPC |
| `VECTOR_DB_COLLECTION` | mitre_v18_1 | Historical examples (694 vectors) |
| `ATTACK_MAPPER_REQUIRE_RAG` | true | Fail fast if VectorAI collection is not ready |
| `ATTACK_VERSION` | 18.1 | Enterprise framework version |
| `MAX_TECHNIQUES_PER_FINDING` | 5 | Policy gate limit |
| `ROUTING_MODE` | local | Default routing for Mapper |

### `prompts.py` -- Prompt Templates

| Prompt | Used By | Purpose |
|--------|---------|---------|
| `SummaryPrompts.SYSTEM_PROMPT` | Reporter | Constrains Gemini to produce a single technical sentence |
| `SummaryPrompts.USER_PROMPT_TEMPLATE` | Reporter | Injects finding evidence into the prompt |
| `AttackMapperPrompts.SYSTEM_PROMPT` | Mapper (cloud) | Structured JSON output schema for ATT&CK mapping |
| `AttackMapperPrompts.CLOUD_RAG_USER_PROMPT_TEMPLATE` | Mapper (cloud) | Includes RAG context + finding details |
| `AttackMapperPrompts.LOCAL_USER_PROMPT_TEMPLATE` | Mapper (local) | RAG-aware Mistral instruction format (### Instruction / ### Reference Examples from Database / ### Log / ### Response) |

## LoRA Adapter Versions

| Version | Notebook | Prompt Structure | Status |
|---------|----------|-----------------|--------|
| v1 | `CSC699LoRA.ipynb` | `### Instruction / ### Log / ### Response` (no RAG section) | Retired -- caused hallucination when RAG was injected at inference |
| **v2** | `CSC699LoRA_RAG_v2.ipynb` | `### Instruction / ### Reference Examples from Database / ### Log / ### Response` | **Active** -- trained with synthetic RAG examples (20% with context, 80% without) |

Both notebooks are in `src/section2_report_map/FineTuningNotebook/`. The v2 adapter is trained on `mistralai/Mistral-7B-Instruct-v0.1` with identical LoRA config (r=16, alpha=16, 7 target modules) and saves to `final_adapter_v2`.

## Usage

### Full Pipeline (Reporter + Mapper)

```powershell
# Set API key
$env:GOOGLE_API_KEY = "your-key"

# Run on a single file (local Mistral LoRA v2, default)
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
# Seed corpus + local mapped findings into VectorAI
python scripts/seed_vector_db.py --attack-corpus data/corpus/enterprise-attack-18.1.json --mapped-dir data/mapped

# Check readiness (exit code 0 = ready, 2 = not ready)
python scripts/check_vector_db.py --json
```

### Seed Data Source (MITRE ATT&CK v18.1)

The Vector DB is seeded from the MITRE ATT&CK Enterprise STIX bundle (v18.1):

- Local canonical file: `data/corpus/enterprise-attack-18.1.json`
- Upstream source: https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack-18.1.json

### Reporter Only

```powershell
python run_reporter.py "data/processed/report.json"
python run_reporter.py --batch data/processed --output-dir data/enriched
```

### Review Mapped Output

```powershell
# Review all MITRE IDs, validation status, and summary for each finding
python scripts/review_mapped.py "data/mapped/report_mapped_20260313_140821.json"
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
      "metadata": {
        "source_agent": "Reporter",
        "db_context": "Actian-VectorAI",
        "framework": "enterprise 18.1",
        "retrieved_examples": 2,
        "validation_gates": {
          "format": true,
          "consistency": true,
          "policy": true
        }
      }
    }
  }
}
```

## Caching

The Reporter caches valid Gemini summaries to avoid redundant API calls.

- **Key**: SHA-256 hash of (prompt version + model + title + description + CVEs + services + ports)
- **Storage**: `data/cache/` as plain text files
- **Invalidation**: Bump `SUMMARY_PROMPT_VERSION` in config when prompts or validation logic change (currently `summary_v3`)

## File Structure

```
src/section2_report_map/
    __init__.py             # Package exports
    reporter.py             # Reporter Agent (Gemini)
    mapper.py               # Mapper Agent (Mistral LoRA v2 + VectorAI)
    validation.py           # Three-gate validation layer
    config.py               # All configuration
    prompts.py              # LLM prompt templates
    FineTuningNotebook/
        CSC699LoRA.ipynb            # v1 training notebook (archived)
        CSC699LoRA_RAG_v2.ipynb     # v2 RAG-aware training notebook

run_section2.py             # Unified CLI (Reporter -> Mapper)
run_reporter.py             # Reporter-only CLI
scripts/review_mapped.py    # Mapped output review utility

data/
    processed/              # Section 1 output (input to Section 2)
    mapped/                 # Section 2 output (enriched with MITRE IDs)
    cache/                  # Reporter summary cache
    corpus/                 # MITRE ATT&CK Enterprise v18.1 STIX bundle

tests/
    test_mapper.py              # Mapper unit tests
    test_reporter.py            # Reporter unit tests
    test_reporter_mock.py       # Reporter cache tests
    manual_integration_test.py  # End-to-end pipeline test (mocked)
```

## Dependencies

| Package | Purpose |
|---------|---------|
| google-genai | Gemini API (Reporter + cloud Mapper) |
| sentence-transformers | Embedding model for VectorAI queries |
| actiancortex | Actian VectorAI client for RAG |
| transformers + peft | Mistral-7B base + LoRA adapter loading |
| bitsandbytes | 4-bit NF4 quantization for local inference |
| torch | PyTorch backend for local inference |
| protobuf >= 6.31.1 | Required by actiancortex (must match gencode version) |

## Performance (Observed on NVIDIA RTX 2000 Ada)

| Metric | Value |
|--------|-------|
| Findings per run | 56 |
| Findings with valid MITRE IDs | 52 (93%) |
| Unique techniques assigned | 19 |
| Avg mapping time per finding | ~30s |
| Total pipeline time (56 findings) | ~30 min |
| Hallucinated / fake IDs | 0 |
