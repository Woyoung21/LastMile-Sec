#!/usr/bin/env python3
"""
Quick test of the Reporter on an enriched JSON file
"""

import json
from pathlib import Path
from src.section2_report_map.reporter import Reporter


def test_reporter():
    """Test reporter with enhanced JSON packets."""
    # Find enriched JSON file (from Section 1 output)
    enhanced_dir = Path("data/processed")
    json_files = list(enhanced_dir.glob("*_enhanced_*.json"))
    
    if not json_files:
        print(f"❌ No enhanced JSON files found in {enhanced_dir}")
        print("   Run regenerate_json.py first to create enriched packets")
        return False
    
    json_file = json_files[0]
    print(f"📄 Testing with: {json_file.name}\n")
    
    try:
        # Load JSON
        with open(json_file) as f:
            packet_data = json.load(f)
        
        print(f"Loaded packet with {len(packet_data.get('findings', []))} findings")
        
        # Initialize reporter
        print("\n🚀 Initializing Reporter...")
        reporter = Reporter()
        
        # Process just first 3 findings as a quick test
        test_findings = packet_data['findings'][:3]
        print(f"\n📋 Generating summaries for first 3 findings:\n")
        
        for i, finding in enumerate(test_findings, 1):
            print(f"Finding {i}: {finding.get('title', 'Unknown')[:60]}")
            summary, _ = reporter.generate_summary(finding)
            print(f"   Summary: {summary}\n")
        
        # Show stats
        stats = reporter.get_stats()
        print(f"📊 Reporter Stats:")
        print(f"   Total processed: {stats['total_findings_processed']}")
        print(f"   Cache hits: {stats['cache_hits']}")
        print(f"   Cache misses: {stats['cache_misses']}")
        
        return True
    
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_reporter()
    exit(0 if success else 1)

