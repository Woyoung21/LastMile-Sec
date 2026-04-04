# Section 4 — LLM Remediation + Self-RAG Verification

Generate vendor-tailored, step-by-step remediation instructions from Section 3 correlated findings using Gemini structured output, then verify each generation with a Self-RAG (Self-Reflective Retrieval Augmented Generation) loop that checks grounding, relevance, and completeness — automatically retrying on failure.

## Architecture

```mermaid
flowchart TD
    Input["*_correlated.json<br/>(Section 3 output)"] --> CLI["CLI Entry Point<br/>cli/remediate.py"]

    CLI --> Iter["Iterate findings with<br/>rag_correlation + technical_summary"]

    Iter --> Assemble["Context Assembly<br/>(generator.py)"]
    Assemble -->|"technical_summary<br/>severity, MITRE IDs<br/>tech_stack, controls_text"| Prompt

    subgraph gen [Generation]
        Prompt["Prompt Template<br/>(prompts.py)"] --> Gemini["Gemini 2.5 Flash<br/>Structured Output"]
        Gemini --> Output["RemediationOutput<br/>(Pydantic schema)"]
    end

    Output --> Verifier

    subgraph selfrag [Self-RAG Verification]
        Verifier["SelfRAGVerifier<br/>(selfrag.py)"]
        Verifier --> G["Grounding Check<br/>Token overlap + LLM judge"]
        Verifier --> R["Relevance Check<br/>Keyword overlap + MITRE ID refs"]
        Verifier --> C["Completeness Check<br/>Top-3 control ID coverage"]
        G --> Result["VerificationResult"]
        R --> Result
        C --> Result
    end

    Result --> Decision{Passed?}
    Decision -->|Yes| Write["Append to metadata<br/>Write *_remediated.json"]
    Decision -->|"No + attempts < 3"| Retry["Format rejection issues<br/>RETRY_PROMPT"]
    Retry --> Prompt
    Decision -->|"No + attempts = 3"| WriteFail["Append to metadata<br/>passed=false"]
```

## How It Works

### 1. Input Parsing

The CLI reads `*_correlated.json` files from Section 3's output directory (`data/correlate/`). For each finding that has both a `technical_summary` and a `rag_correlation` block, it feeds the finding into the Self-RAG loop.

### 2. Context Assembly

[`generator.py :: _format_controls_text`](generator.py) extracts the correlated controls from Neo4j (best match + vendor controls + framework controls) and formats them into a human-readable text block. It also collects the finding's MITRE ATT&CK IDs, severity, technical summary, and the client's tech stack from `.env`.

### 3. Prompt Construction

These variables are injected into a [`ChatPromptTemplate`](prompts.py) with a system message that instructs Gemini to act as a senior security engineer writing for L1/L2 ops staff. The key rule: **base every command, path, and setting on the SOURCE CONTROLS provided — do not invent**.

### 4. Structured Generation

Gemini 2.5 Flash is called via LangChain's `with_structured_output()`, which forces the response to conform to the [`RemediationOutput`](schemas.py) Pydantic schema. This guarantees the output has typed `steps[]`, `priority`, `estimated_effort`, `prerequisites`, `verification`, and `source_control_ids`.

### 5. Self-RAG Verification

The generated output goes through three independent checks in [`SelfRAGVerifier`](selfrag.py):

| Check | What it measures | How | Default threshold |
|-------|-----------------|-----|-------------------|
| **Grounding** | Are steps factually backed by source controls? | Token-overlap heuristic; if < 1.0, an LLM-as-judge (Gemini at temp 0.0) rates each step as SUPPORTED / PARTIALLY / NOT | >= 0.7 |
| **Relevance** | Do steps address the actual finding? | Keyword overlap with `technical_summary` + explicit MITRE ATT&CK ID string presence | >= 0.5 |
| **Completeness** | Are top correlated controls covered? | Prefix matching of top-3 control IDs against `source_control_ids` in output | >= 0.5 |

### 6. Retry Loop

If any threshold is not met, the system formats the verification issues into human-readable rejection feedback and re-invokes Gemini with the [`RETRY_PROMPT`](prompts.py), which includes the original context plus the specific rejection reasons. This runs up to **3 total attempts** (1 initial + 2 retries). If all attempts fail, the last result is returned with `passed=false`.

### 7. Output

The `RemediationOutput` and `VerificationResult` are serialized into the finding's `metadata.remediation` block and written to `data/remediated/*_remediated.json`.

## Prerequisites

1. **`GOOGLE_API_KEY`** set in `.env` for Gemini API access.
2. **Section 3 correlated output** — at least one `*_correlated.json` file in `data/correlate/`.
3. **Dependencies** installed from the project [`requirements.txt`](../../requirements.txt).

## Commands

Run from the **repository root** (`LastMile-Sec`).

```bash
# Generate remediation for all correlated findings
python -m src.section4_remediation.cli.remediate

# Single file with limited findings
python -m src.section4_remediation.cli.remediate --json "data/correlate/your_correlated.json" --max-findings 5

# Override tech stack
python -m src.section4_remediation.cli.remediate --tech-stack "Windows Server,Ubuntu Linux,NIST SP 800-53"

# Skip LLM-as-judge grounding (faster, heuristic-only verification)
python -m src.section4_remediation.cli.remediate --skip-llm-judge
```

Terminal output shows one line per finding with verification scores:

```
Processing wrccdc.2024-02-17.105657_mapped_20260306_152137_correlated.json
  [PASS] e1dc1510-6944-4619-8d76-ffa42cca3fee -> 4 steps (G:1.00 R:0.64 attempts:1)
  [PASS] e01dccbd-f9bf-405d-acd3-f1964ceed79c -> 3 steps (G:1.00 R:0.67 attempts:2)
  [FAIL] a2aa1871-6f35-4773-aa98-a6ec3e9046e7 -> 4 steps (G:1.00 R:0.71 attempts:3)
  Written to data\remediated\..._remediated.json

Done. 66 findings remediated.
```

## Output Schema

Each remediated finding gets this structure in `metadata.remediation`:

```json
{
  "steps": [
    {
      "step_number": 1,
      "title": "Disable anonymous 'Everyone' permissions",
      "command_or_action": "Navigate to Computer Configuration\\Policies\\...",
      "explanation": "This setting prevents anonymous users from ...",
      "vendor_product": "Windows Server"
    }
  ],
  "priority": "high",
  "estimated_effort": "30 minutes",
  "prerequisites": [
    "Administrative access to the target Windows Server."
  ],
  "verification_procedure": "Navigate to the UI path and confirm ...",
  "source_control_ids": ["2.3.10.4", "2.3.10.3", "2.3.11.2"],
  "model": "gemini-2.5-flash",
  "prompt_version": "remediation_v1",
  "generated_at": "2026-04-04T01:50:00+00:00",
  "selfrag_verification": {
    "grounding_score": 1.0,
    "relevance_score": 0.68,
    "completeness_score": 1.0,
    "passed": true,
    "issues": [],
    "attempts": 1
  }
}
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GOOGLE_API_KEY` | *(required)* | Gemini API key |
| `GEMINI_MODEL` | `gemini-2.5-flash` | LLM model for generation and grounding judge |
| `GLOBAL_TECH_STACK` | `Windows Server,Meraki MS,M365,NIST SP 800-53` | Comma-separated vendor names for scoping remediation |
| `SELFRAG_GROUNDING_THRESHOLD` | `0.7` | Minimum grounding score to pass |
| `SELFRAG_RELEVANCE_THRESHOLD` | `0.5` | Minimum relevance score to pass |
| `SELFRAG_COMPLETENESS_THRESHOLD` | `0.5` | Minimum completeness score to pass |
| `SELFRAG_MAX_RETRIES` | `2` | Max retry attempts on verification failure (3 total) |
| `REMEDIATION_LLM_TEMPERATURE` | `0.2` | LLM temperature for generation |
| `CORRELATED_JSON_DIR` | `data/correlate` | Input directory (Section 3 output) |
| `REMEDIATED_JSON_DIR` | `data/remediated` | Output directory |

## File Map

```
src/section4_remediation/
├── __init__.py          # Package metadata
├── config.py            # Env vars, thresholds, paths
├── schemas.py           # Pydantic models (RemediationOutput, VerificationResult)
├── prompts.py           # 3 ChatPromptTemplates (generate, grounding judge, retry)
├── generator.py         # Gemini structured output generation + metadata serialization
├── selfrag.py           # Self-RAG verifier (3 checks) + retry loop orchestration
└── cli/
    ├── __init__.py
    └── remediate.py     # CLI entry point, file I/O, finding iteration
```

## Data Directories

| Path | Role |
|------|------|
| `data/correlate/*.json` | Input — Section 3 correlated findings |
| `data/remediated/*.json` | Output — findings with `metadata.remediation` block |

## Tests

From repo root:

```bash
python -m pytest tests/section4 -v
```

Covers Pydantic schema validation, generator structured output (mocked LangChain RunnableSequence), Self-RAG heuristic grounding, relevance scoring, completeness prefix matching, SelfRAGVerifier pass/fail aggregation, metadata serialization, CLI finding iteration, and output file writing. No live Gemini or API calls required.
