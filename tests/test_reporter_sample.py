#!/usr/bin/env python3
"""Run Reporter on the full JSON packet to generate and save summaries."""

import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.section2_report_map.reporter import Reporter


def run_reporter_on_full_packet():
    """Run Reporter on all findings from the latest enhanced JSON."""
    
    # Find the latest enhanced JSON file
    processed_dir = Path("data/processed")
    enhanced_files = sorted(processed_dir.glob("*enhanced*.json"), reverse=True)
    
    if not enhanced_files:
        print("❌ No enhanced JSON files found")
        return
    
    json_file = enhanced_files[0]
    print(f"📄 Processing file: {json_file.name}\n")
    
    # Load the JSON
    with open(json_file) as f:
        packet_data = json.load(f)
    
    print(f"Total findings in packet: {len(packet_data.get('findings', []))}")
    
    # Initialize Reporter
    try:
        reporter = Reporter()
        print("✅ Reporter initialized successfully\n")
    except Exception as e:
        print(f"❌ Failed to initialize Reporter: {e}")
        return
    
    # Process ALL findings
    max_findings = None
    print(f"🔄 Processing ALL findings in the packet...\n")
    
    try:
        enriched_packet = reporter.process_packet(packet_data, max_findings=max_findings)
        
        # ACTUALLY SAVE THE FILE TO DISK
        saved_file = reporter.save_enriched_packet(enriched_packet, processed_dir)
        
        # Display results
        print(f"\n✅ Successfully generated summaries and saved file!\n")
        print("=" * 80)
        
        findings = enriched_packet.get('findings', [])
        for i, finding in enumerate(findings, 1):
            metadata = finding.get('metadata', {})
            if 'technical_summary' in metadata:
                summary = metadata['technical_summary']
                # Only print the AI-generated single sentence
                print(f"[Finding {i}]: {summary}")
        
        print("\n" + "=" * 80)
        print("\nReporter Stats:")
        stats = reporter.get_stats()
        for key, val in stats.items():
            print(f"  {key}: {val}")
            
    except Exception as e:
        print(f"❌ Error during processing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_reporter_on_full_packet()