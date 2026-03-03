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
| **3. Correlation + RAG** | Add client context → Query vendor docs → Generate remediation | Planned |
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

## Project Structure

```
LastMile-Sec/
├── run.py                         # Section 1 CLI (parse files)
├── run_reporter.py                # Section 2 Reporter-only CLI
├── run_section2.py                # Section 2 full pipeline CLI (Reporter + Mapper)
├── requirements.txt
├── src/
│   ├── section1_ingestion/
│   │   ├── schemas.py             # Pydantic data models
│   │   ├── normalizer.py          # Orchestrator
│   │   └── parsers/
│   │       ├── base_parser.py     # Abstract base class
│   │       ├── csv_parser.py      # CSV vulnerability reports
│   │       ├── pcap_parser.py     # Network packet captures
│   │       ├── pdf_parser.py      # PDF (regex-based)
│   │       └── pdf_parser_langextract.py  # PDF (LLM-powered)
│   └── section2_report_map/
│       ├── reporter.py            # Reporter Agent (Gemini summaries)
│       ├── mapper.py              # Mapper Agent (Mistral LoRA + VectorAI RAG)
│       ├── config.py              # API keys, models, thresholds
│       └── prompts.py             # LLM prompt templates
├── tests/
│   ├── test_section1.py           # Section 1 unit tests
│   ├── test_reporter.py           # Reporter unit tests
│   ├── test_mapper.py             # Mapper unit tests
│   └── manual_integration_test.py # End-to-end pipeline test
├── data/
│   ├── raw/                       # Input files (not committed)
│   ├── processed/                 # Section 1 output (normalized JSON)
│   ├── mapped/                    # Section 2 output (enriched with MITRE IDs)
│   └── cache/                     # Reporter summary cache
└── Weekly Review/                 # Project documentation
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
| CSV | csv_parser | ✅ Works great |
| PCAP | pcap_parser | ✅ Works |
| PDF | pdf_parser | ⚠️ Basic (use LangExtract for better results) |

## License

MIT License - See LICENSE file
