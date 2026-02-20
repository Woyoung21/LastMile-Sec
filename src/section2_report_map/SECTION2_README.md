# Section 2: Report & Mapper

## Overview

Section 2 takes the normalized JSON packets from Section 1 (Ingestion) and enriches them with:

1. **Technical Summary Sentences** - Generated via Gemini LLM
2. **MITRE ATT&CK Mappings** - Future integration (not yet implemented)
3. **Risk Scoring & Prioritization** - Future enhancement

## Architecture

```
Section 1 (Ingestion)
    ↓
    JSON Packets (552 findings from PDF, 545 from CSV)
    ↓
Section 2 (Reporter)
    ├── Load enriched packets
    ├── For each finding:
    │   ├── Generate technical summary (via Gemini)
    │   ├── Cache summary
    │   └── Add to metadata
    ├── Output enriched packets
    └── Ready for Section 3 (ATT&CK Mapper)
    ↓
Enhanced JSON with summaries
```

## Components

### `reporter.py`
Main Reporter class that:
- Loads JSON packets from Section 1
- Generates one-sentence technical summaries per finding using Gemini
- Implements intelligent caching to avoid re-summarizing
- Adds summaries to finding metadata
- Outputs enriched packets ready for mapping

**Key Methods:**
- `generate_summary(finding)` - Generate summary for single finding
- `process_packet(packet_data)` - Process entire JSON packet
- `process_json_file(path)` - Load and process JSON file
- `save_enriched_packet(packet, output_dir)` - Save enriched output

### `config.py`
Configuration settings for:
- **Gemini API**: Model selection, generation parameters, rate limiting
- **Processing**: Concurrency, retry logic, timeouts
- **Caching**: Enable/disable, cache directory
- **MITRE ATT&CK Mapper** (future): Framework version, confidence thresholds

### `prompts.py`
System and user prompts for:
- **Summary generation**: Detailed requirements for concise technical summaries
- **ATT&CK mapping** (future): Guidelines for technique classification

## Usage

### Option 1: Process Single File
```bash
python run_reporter.py data/processed/Vulnerability_Scan_Report_enhanced_20260220_110347.json
```

### Option 2: Process All Enhanced JSON Files
```bash
python run_reporter.py --batch data/processed/ --output-dir data/enriched/
```

### Option 3: Quick Test
```bash
python test_reporter.py
```

## API Configuration

Before running, ensure you have the Gemini API key configured:

```bash
export GOOGLE_API_KEY='your-api-key-here'
```

Or set it in your environment:
```python
import os
os.environ['GOOGLE_API_KEY'] = 'your-api-key-here'
```

## Summary Generation

### Input
Each finding contains:
- Severity level
- Title
- Description (first 500 chars)
- CVE IDs
- Services (SSH, HTTP, etc.)
- Ports
- CVSS score

### Output
A single technical sentence following these requirements:
- **Exactly ONE sentence** (ends with period)
- **Technical but understandable**
- **15-30 words**
- **Includes**: vulnerability type, affected component, potential impact
- **References CVE IDs** when available
- **Active voice**

### Example Summaries
```
"Remote code execution vulnerability in OpenSSH versions < 9.3p2 allows unauthenticated attackers to execute arbitrary commands via protocol manipulation."

"Default community names for SNMP agent (port 161) enable unauthenticated information disclosure of system configuration."

"SQL injection vulnerability in login form allows attackers to bypass authentication and access database records."
```

## Caching Strategy

Reporter implements intelligent caching to avoid regenerating summaries:

- **Cache Key**: MD5 hash of finding title + description
- **Cache Storage**: `data/cache/` directory
- **Cache Format**: Plain text, one summary per file
- **Hit Rate**: Tracked for performance monitoring

Benefits:
- ⚡ Fast re-runs
- 💰 Reduced API calls  
- 📊 Lower costs

## Performance

Processing ~550 findings:
- **With Cache**: < 1 second (if all cached)
- **Without Cache**: ~5-10 minutes (due to Gemini rate limiting)
- **API Calls**: Max 1 concurrent (respects rate limits)
- **Cache Hit Rate**: Typically 80%+ on re-runs

## Error Handling

Reporter includes:
- **Retry Logic**: 3 attempts with exponential backoff
- **Timeout Protection**: 30-second request timeout
- **Graceful Degradation**: Returns error message if generation fails
- **Rate Limit Respect**: Single concurrent request

## Future Enhancement: MITRE ATT&CK Mapper

When implemented, the mapper will:

1. Take enriched packets with technical summaries
2. Identify attack patterns and techniques
3. Map to MITRE ATT&CK enterprise framework (v13.0)
4. Assign confidence scores for each mapping
5. Output structured attack methodology analysis

This will enable:
- Threat actor profiling
- Campaign tracking
- Security control gap analysis
- Risk prioritization by technique

## File Structure

```
src/section2_report_map/
├── __init__.py          # Package initialization
├── reporter.py          # Main Reporter class
├── config.py            # Configuration settings
└── prompts.py           # LLM prompts

data/
├── processed/           # Section 1 output (enhanced JSON files)
├── enriched/            # Section 2 output (with summaries)
└── cache/               # Reporter cache

run_reporter.py         # CLI entry point
test_reporter.py        # Quick test script
```

## Next Steps

1. ✅ Section 1: PDF/CSV ingestion with metadata extraction
2. ✅ Section 2: Reporter with Gemini summaries (current)
3. 📋 Section 3: MITRE ATT&CK mapper integration
4. 🎯 Section 4: Risk scoring and prioritization
