#!/usr/bin/env python3
"""Test Reporter structure with mock Gemini responses"""

import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))


class MockReporter:
    """Mock Reporter for testing without Gemini API."""
    
    def __init__(self):
        self.report_count = 0
        
    def generate_summary(self, finding_dict: dict) -> str:
        """Generate mock summary (in real version, uses Gemini)."""
        title = finding_dict.get('title', '')
        severity = finding_dict.get('severity', 'unknown')
        cvss = finding_dict.get('cvss_score', 'unknown')
        cves = finding_dict.get('cve_ids', [])
        
        # Generate a simple summary
        cve_str = f" ({', '.join(cves[:2])})" if cves else ""
        summary = f"[{severity.upper()}] {title} with CVSS {cvss}{cve_str} requires immediate remediation."
        return summary
    
    def process_packet(self, packet_data: dict, max_findings=None):
        """Process packet with mock summaries."""
        findings = packet_data.get('findings', [])
        
        if max_findings and len(findings) > max_findings:
            findings = findings[:max_findings]
            print(f"\n📋 Processing first {max_findings} findings (MOCK MODE)...")
        else:
            print(f"\n📋 Processing packet with {len(findings)} findings (MOCK MODE)...")
        
        for i, finding in enumerate(findings, 1):
            summary = self.generate_summary(finding)
            
            if 'metadata' not in finding:
                finding['metadata'] = {}
            
            finding['metadata']['technical_summary'] = summary
            finding['metadata']['summary_source'] = 'mock'
            
            if i % 5 == 0 or i == 1:
                print(f"  ✓ {i}/{len(findings)} findings processed")
        
        self.report_count += len(findings)
        
        if 'metadata' not in packet_data:
            packet_data['metadata'] = {}
        
        packet_data['metadata']['reporter_stats'] = {
            'total_findings_summarized': len(findings),
            'mock_mode': True,
        }
        
        return packet_data
    
    def get_stats(self):
        return {'total_findings_processed': self.report_count, 'mode': 'mock'}


def test_reporter_mock():
    """Test Reporter with mock summaries on first 3-6 findings."""
    
    # Find the latest enhanced JSON file
    processed_dir = Path("data/processed")
    enhanced_files = sorted(processed_dir.glob("*enhanced*.json"), reverse=True)
    
    if not enhanced_files:
        print("❌ No enhanced JSON files found")
        return
    
    json_file = enhanced_files[0]
    print(f"📄 Testing with: {json_file.name}\n")
    
    # Load the JSON
    with open(json_file) as f:
        packet_data = json.load(f)
    
    print(f"Total findings in packet: {len(packet_data.get('findings', []))}")
    
    # Initialize Mock Reporter
    reporter = MockReporter()
    print("✅ Mock Reporter initialized (DEMO MODE)\n")
    
    # Process with limit (first 5 findings)
    max_findings = 5
    
    try:
        enriched_packet = reporter.process_packet(packet_data, max_findings=max_findings)
        
        # Display results
        print(f"\n✅ Successfully generated mock summaries!\n")
        print("=" * 90)
        
        findings = enriched_packet.get('findings', [])[:max_findings]
        for i, finding in enumerate(findings, 1):
            print(f"\n📌 [Finding {i}]")
            print(f"   Title: {finding.get('title', 'N/A')[:72]}")
            print(f"   Severity: {finding.get('severity', 'N/A').upper()}")
            print(f"   CVSS: {finding.get('cvss_score', 'N/A')}")
            
            metadata = finding.get('metadata', {})
            if 'technical_summary' in metadata:
                summary = metadata['technical_summary']
                print(f"   Summary: {summary}")
            
            if 'nvt_oid' in metadata:
                print(f"   OID: {metadata['nvt_oid']}")
            if 'ports' in metadata and metadata['ports']:
                print(f"   Ports: {metadata['ports']}")
            if 'services' in metadata and metadata['services']:
                print(f"   Services: {', '.join(metadata['services'])}")
        
        print("\n" + "=" * 90)
        print("\nReporter Stats:")
        stats = reporter.get_stats()
        for key, val in stats.items():
            print(f"  {key}: {val}")
        
        print("\n💡 This is MOCK MODE - using placeholder summaries.")
        print("   To enable Gemini API:")
        print("   1. Set: $env:GOOGLE_API_KEY='sk-...'")
        print("   2. Run: python test_reporter_sample.py\n")
        
    except Exception as e:
        print(f"❌ Error during processing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_reporter_mock()
