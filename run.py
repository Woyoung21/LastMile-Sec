#!/usr/bin/env python3
"""
LastMile-Sec - Simple CLI Runner

Usage:
    python run.py <file_path>
    python run.py <file_path> --pdf-parser langextract
    python run.py <file_path> --pdf-parser auto
"""

import argparse
import sys
from pathlib import Path

from src.section1_ingestion import Normalizer


def main():
    parser = argparse.ArgumentParser(
        description="LastMile-Sec ingestion CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python run.py data/raw/report.csv\n"
            "  python run.py data/raw/report.pdf --pdf-parser langextract\n"
            "  python run.py data/raw/capture.pcap\n"
        ),
    )
    parser.add_argument("file_path", help="Path to the file to ingest")
    parser.add_argument(
        "--pdf-parser",
        choices=["regex", "langextract", "auto"],
        default="regex",
        dest="pdf_parser",
        help="PDF parser backend: regex (default), langextract (Gemini), or auto",
    )

    args = parser.parse_args()

    if not Path(args.file_path).exists():
        print(f"Error: File not found: {args.file_path}")
        sys.exit(1)

    print(f"Parsing: {args.file_path}")
    print(f"PDF parser: {args.pdf_parser}")
    print("-" * 50)

    normalizer = Normalizer(
        output_dir="data/processed",
        pdf_parser=args.pdf_parser,
    )

    packet, output_path = normalizer.ingest_and_save(args.file_path)

    print(f"Source: {packet.source_file}")
    print(f"Type: {packet.source_type.value}")
    print(f"Findings: {packet.finding_count}")
    print(f"  Critical: {packet.critical_count}")
    print(f"  High: {packet.high_count}")
    print("-" * 50)
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()
