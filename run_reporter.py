#!/usr/bin/env python3
"""
Section 2 Reporter CLI

Processes JSON packets from Section 1 and generates technical summaries.

Usage:
    python run_reporter.py <input_json> [--output-dir <path>]
    python run_reporter.py --batch <input_dir> [--output-dir <path>]
"""

import json
import sys
from pathlib import Path
from typing import Optional

from src.section2_report_map.reporter import Reporter


def process_single_file(json_file: str, output_dir: Optional[Path] = None) -> bool:
    """Process a single JSON file."""
    json_path = Path(json_file)
    
    if not json_path.exists():
        print(f"❌ File not found: {json_file}")
        return False
    
    try:
        # Initialize reporter
        reporter = Reporter()
        
        # Process the file
        enriched_packet = reporter.process_json_file(json_path)
        
        if enriched_packet is None:
            return False
        
        # Save enriched packet
        if output_dir is None:
            output_dir = json_path.parent
        
        reporter.save_enriched_packet(enriched_packet, output_dir)
        
        # Show stats
        stats = reporter.get_stats()
        print(f"\n📊 Processing Complete:")
        print(f"   Findings processed: {stats['total_findings_processed']}")
        print(f"   Cache hits: {stats['cache_hits']}")
        print(f"   Cache misses: {stats['cache_misses']}")
        print(f"   Cache hit rate: {stats['cache_hit_rate']:.1%}")
        
        return True
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def process_batch(input_dir: str, output_dir: Optional[Path] = None) -> bool:
    """Process all JSON files in a directory."""
    input_path = Path(input_dir)
    
    if not input_path.is_dir():
        print(f"❌ Directory not found: {input_dir}")
        return False
    
    json_files = sorted(input_path.glob("*.json"))
    
    if not json_files:
        print(f"❌ No JSON files found in {input_dir}")
        return False
    
    print(f"📁 Found {len(json_files)} JSON files to process")
    
    try:
        reporter = Reporter()
        
        for json_file in json_files:
            enriched_packet = reporter.process_json_file(json_file)
            
            if enriched_packet and output_dir:
                reporter.save_enriched_packet(enriched_packet, output_dir)
        
        # Show stats
        stats = reporter.get_stats()
        print(f"\n📊 Batch Processing Complete:")
        print(f"   Findings processed: {stats['total_findings_processed']}")
        print(f"   Cache hits: {stats['cache_hits']}")
        print(f"   Cache misses: {stats['cache_misses']}")
        print(f"   Cache hit rate: {stats['cache_hit_rate']:.1%}")
        
        return True
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    output_dir = None
    
    # Parse arguments
    if "--output-dir" in sys.argv:
        idx = sys.argv.index("--output-dir")
        if idx + 1 < len(sys.argv):
            output_dir = Path(sys.argv[idx + 1])
    
    if sys.argv[1] == "--batch" and len(sys.argv) > 2:
        success = process_batch(sys.argv[2], output_dir)
    else:
        success = process_single_file(sys.argv[1], output_dir)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
