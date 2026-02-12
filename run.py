#!/usr/bin/env python3
"""
LastMile-Sec - Simple CLI Runner

Usage:
    python run.py <file_path>
    python run.py data/raw/report.csv
    python run.py data/raw/capture.pcap
"""

import sys
from pathlib import Path

from src.section1_ingestion import Normalizer


def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py <file_path>")
        print("")
        print("Examples:")
        print("  python run.py data/raw/report.csv")
        print("  python run.py data/raw/capture.pcap")
        print("  python run.py data/raw/report.pdf")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not Path(file_path).exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    print(f"Parsing: {file_path}")
    print("-" * 50)
    
    # Create normalizer with output directory
    normalizer = Normalizer(output_dir="data/processed")
    
    # Parse and save
    packet, output_path = normalizer.ingest_and_save(file_path)
    
    # Show results
    print(f"Source: {packet.source_file}")
    print(f"Type: {packet.source_type.value}")
    print(f"Findings: {packet.finding_count}")
    print(f"  Critical: {packet.critical_count}")
    print(f"  High: {packet.high_count}")
    print("-" * 50)
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()
