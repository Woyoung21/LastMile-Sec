"""
Comparison script: Manual PDFParser vs LangExtract parser

Runs both parsers on the same PDF and compares their extraction quality.
THIS WILL USE API TOKENS - LangExtract requires Google API calls.

Usage:
    python compare_parsers.py
    
Requires:
    GOOGLE_API_KEY environment variable to be set
"""

import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if it exists
load_dotenv()

from src.section1_ingestion.parsers.pdf_parser import PDFParser
from src.section1_ingestion.parsers.pdf_parser_langextract import PDFParserLangExtract


def format_findings(findings):
    """Format findings for display."""
    if not findings:
        return "  (No findings extracted)"
    
    lines = []
    for i, finding in enumerate(findings, 1):
        lines.append(f"  Finding {i}:")
        lines.append(f"    Title: {finding.title}")
        lines.append(f"    Severity: {finding.severity.value if finding.severity else 'Unknown'}")
        lines.append(f"    Description: {finding.description[:100]}..." if len(finding.description) > 100 else f"    Description: {finding.description}")
        
        if finding.cve_ids:
            lines.append(f"    CVEs: {', '.join(finding.cve_ids)}")
        
        if finding.affected_assets:
            assets = [a.identifier for a in finding.affected_assets]
            lines.append(f"    Affected Assets: {', '.join(assets)}")
        
        if finding.cvss_score:
            lines.append(f"    CVSS Score: {finding.cvss_score}")
        
        if finding.recommendations:
            lines.append(f"    Recommendations: {finding.recommendations[0][:80]}..." if len(finding.recommendations[0]) > 80 else f"    Recommendations: {finding.recommendations[0]}")
    
    return "\n".join(lines)


def main():
    # PDF file path
    pdf_path = Path("data/raw/Vulnerability Scan Report (By Device).pdf")
    
    if not pdf_path.exists():
        print(f"❌ Error: PDF not found at {pdf_path}")
        return
    
    print(f"📄 Testing PDF: {pdf_path}")
    print(f"   File size: {pdf_path.stat().st_size / 1024:.1f} KB\n")
    
    # Test 1: Manual PDFParser (regex-based)
    print("=" * 80)
    print("1️⃣  MANUAL PDF PARSER (Regex-based)")
    print("=" * 80)
    
    try:
        parser1 = PDFParser(pdf_path)
        findings1 = parser1.parse()
        
        print(f"✓ Extracted {len(findings1)} findings\n")
        print(format_findings(findings1))
        
        if parser1.warnings:
            print(f"\n⚠️  Warnings: {len(parser1.warnings)}")
            for w in parser1.warnings[:3]:
                print(f"   - {w}")
        
        if parser1.errors:
            print(f"\n❌ Errors: {len(parser1.errors)}")
            for e in parser1.errors[:3]:
                print(f"   - {e}")
    
    except Exception as e:
        print(f"❌ Error running manual parser: {e}")
        findings1 = []
    
    # Test 2: LangExtract Parser (LLM-based)
    print("\n" + "=" * 80)
    print("2️⃣  LANGEXTRACT PARSER (LLM-powered with Gemini)")
    print("=" * 80)
    print("⏳ This will call the Google Generative AI API...\n")
    
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("❌ Error: GOOGLE_API_KEY environment variable not set")
        print("   Set it with: $env:GOOGLE_API_KEY='your-key'")
        findings2 = []
    else:
        try:
            parser2 = PDFParserLangExtract(pdf_path, api_key=api_key)
            findings2 = parser2.parse()
            
            print(f"✓ Extracted {len(findings2)} findings\n")
            print(format_findings(findings2))
            
            if parser2.warnings:
                print(f"\n⚠️  Warnings: {len(parser2.warnings)}")
                for w in parser2.warnings[:3]:
                    print(f"   - {w}")
            
            if parser2.errors:
                print(f"\n❌ Errors: {len(parser2.errors)}")
                for e in parser2.errors[:3]:
                    print(f"   - {e}")
        
        except Exception as e:
            print(f"❌ Error running LangExtract parser: {e}")
            import traceback
            traceback.print_exc()
            findings2 = []
    
    # Comparison
    print("\n" + "=" * 80)
    print("📊 COMPARISON")
    print("=" * 80)
    
    print(f"\nManual Parser:     {len(findings1)} findings")
    print(f"LangExtract Parser: {len(findings2)} findings")
    
    # Count by severity
    def count_by_severity(findings):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for f in findings:
            severity = f.severity.value if f.severity else "unknown"
            if severity in counts:
                counts[severity] += 1
        return counts
    
    counts1 = count_by_severity(findings1)
    counts2 = count_by_severity(findings2)
    
    print(f"\nManual Parser Breakdown:")
    for sev, count in counts1.items():
        if count > 0:
            print(f"  {sev.capitalize()}: {count}")
    
    print(f"\nLangExtract Parser Breakdown:")
    for sev, count in counts2.items():
        if count > 0:
            print(f"  {sev.capitalize()}: {count}")
    
    # CVE extraction comparison
    cves1 = []
    for f in findings1:
        cves1.extend(f.cve_ids)
    cves1 = list(set(cves1))
    
    cves2 = []
    for f in findings2:
        cves2.extend(f.cve_ids)
    cves2 = list(set(cves2))
    
    if cves1 or cves2:
        print(f"\nCVE Extraction:")
        print(f"  Manual Parser: {len(cves1)} unique CVEs")
        if cves1:
            print(f"    Examples: {', '.join(cves1[:3])}")
        
        print(f"  LangExtract: {len(cves2)} unique CVEs")
        if cves2:
            print(f"    Examples: {', '.join(cves2[:3])}")
    
    # CVSS scores comparison
    cvss1 = [f for f in findings1 if f.cvss_score]
    cvss2 = [f for f in findings2 if f.cvss_score]
    
    print(f"\nCVSS Score Extraction:")
    print(f"  Manual Parser: {len(cvss1)}/{len(findings1)} findings have CVSS scores")
    print(f"  LangExtract: {len(cvss2)}/{len(findings2)} findings have CVSS scores")
    
    # Asset identification comparison
    assets1 = set()
    for f in findings1:
        assets1.update([a.identifier for a in f.affected_assets])
    
    assets2 = set()
    for f in findings2:
        assets2.update([a.identifier for a in f.affected_assets])
    
    print(f"\nAsset Identification:")
    print(f"  Manual Parser: {len(assets1)} unique assets")
    print(f"  LangExtract: {len(assets2)} unique assets")
    
    print("\n" + "=" * 80)
    print("✅ Comparison complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()
