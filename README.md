# LastMile-Sec

**Automated Last-Mile Security Remediation Pipeline**

Transform vulnerability reports into actionable, environment-specific remediation steps that L1/L2 engineers can implement.

## Problem

Translating vulnerability/penetration test reports into concrete hardening steps requires expensive senior engineers with cross-domain expertise. This is an industry-wide bottleneck.

## Solution

A 4-stage AI pipeline that automates the "last mile" of security remediation:

| Section | Description |
|---------|-------------|
| **1. Ingestion** | Parse PDFs, CSV, PCAP → Normalized JSON |
| **2. Reporter & Mapper** | Summarize events → Map to MITRE ATT&CK IDs |
| **3. Correlation + RAG** | Add client context → Query vendor docs → Generate remediation |
| **4. Output** | Step-by-step instructions for L1/L2 engineers |

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
├── run.py                         # CLI tool to parse files
├── requirements.txt
├── src/
│   └── section1_ingestion/
│       ├── schemas.py             # Pydantic data models
│       ├── normalizer.py          # Orchestrator
│       └── parsers/
│           ├── base_parser.py     # Abstract base class
│           ├── csv_parser.py      # CSV vulnerability reports
│           ├── pcap_parser.py     # Network packet captures
│           ├── pdf_parser.py      # PDF (regex-based)
│           └── pdf_parser_langextract.py  # PDF (LLM-powered)
├── tests/
│   └── test_section1.py           # Unit tests
├── data/
│   ├── raw/                       # Input files (not committed)
│   └── processed/                 # Output JSON packets
└── Weekly Review/                 # Project documentation
```

## Usage

### Quick Start - Parse Any File

```powershell
# Activate virtual environment
.\venv\Scripts\activate

# Parse a CSV vulnerability report
python run.py "data/raw/your_report.csv"

# Parse a PCAP network capture
python run.py "data/raw/your_capture.pcap"

# Parse a PDF report
python run.py "data/raw/your_report.pdf"
```

Output is saved to `data/processed/` as JSON.

### Run Tests

```powershell
.\venv\Scripts\activate
python -m pytest tests/ -v
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
