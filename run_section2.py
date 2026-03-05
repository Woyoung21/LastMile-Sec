#!/usr/bin/env python3
"""
Section 2 Pipeline CLI — Reporter + Mapper

Processes Section 1 JSON packets through the full Section 2 pipeline:
  1. Reporter  — generates a technical summary per finding (Gemini)
  2. Mapper    — maps each summarised finding to MITRE ATT&CK IDs
                 via Actian VectorAI RAG + local Mistral-7B LoRA

Usage:
    python run_section2.py <input_json> [--output-dir <path>] [--routing-mode local|cloud] [--max-findings N]
    python run_section2.py --batch <input_dir> [--output-dir <path>] [--routing-mode local|cloud]

Examples:
    python run_section2.py "data/processed/report.json"
    python run_section2.py "data/processed/report.json" --routing-mode local --max-findings 10
    python run_section2.py --batch data/processed --output-dir data/mapped
"""

import json
import sys
from pathlib import Path

from src.section2_report_map.reporter import Reporter
from src.section2_report_map.mapper import Mapper


def run_pipeline(
    json_path: Path,
    output_dir: Path,
    routing_mode: str = "local",
    max_findings: int | None = None,
) -> bool:
    """Run the full Reporter -> Mapper pipeline on a single JSON file."""
    if not json_path.exists():
        print(f"File not found: {json_path}")
        return False

    print(f"\n{'=' * 60}")
    print(f"  Section 2 Pipeline: {json_path.name}")
    print(f"  Mapper routing: {routing_mode} (Mistral-7B LoRA)"
          if routing_mode == "local"
          else f"  Mapper routing: {routing_mode} (Gemini cloud)")
    print(f"{'=' * 60}")

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            packet_data = json.load(f)
    except Exception as exc:
        print(f"Failed to load JSON: {exc}")
        return False

    finding_count = len(packet_data.get("findings", []))
    print(f"\nLoaded packet: {finding_count} findings from {packet_data.get('source_file', 'unknown')}")

    # --- Step 1: Reporter ---
    print("\n--- Step 1: Reporter Agent (Gemini summary generation) ---")
    try:
        reporter = Reporter()
        packet_data = reporter.process_packet(packet_data, max_findings=max_findings)

        stats = reporter.get_stats()
        print(f"  Findings summarised: {stats['total_findings_processed']}")
        print(f"  Cache hit rate: {stats['cache_hit_rate']:.0%}")
    except Exception as exc:
        print(f"Reporter failed: {exc}")
        return False

    # --- Step 2: Mapper ---
    print(f"\n--- Step 2: Mapper Agent (Actian VectorAI RAG + {routing_mode}) ---")
    try:
        mapper = Mapper(routing_mode=routing_mode)
        packet_data = mapper.process_packet(packet_data, max_findings=max_findings)
    except Exception as exc:
        print(f"Mapper failed: {exc}")
        return False

    # --- Save output ---
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = mapper.save_mapped_packet(packet_data, output_dir)

    if output_path:
        print(f"\nPipeline complete. Output: {output_path}")
        _print_sample_results(packet_data)
        return True

    return False


def _print_sample_results(packet_data: dict, n: int = 3):
    """Print a quick preview of mapped findings."""
    findings = packet_data.get("findings", [])
    mapped = [f for f in findings if f.get("metadata", {}).get("mitre_mapping", {}).get("mitre_ids")]
    mapper_stats = packet_data.get("metadata", {}).get("mapper_stats", {})
    processed_findings = mapper_stats.get("total_findings_mapped", 0)
    findings_with_valid_ids = len(mapped)
    db_status = mapper_stats.get("vector_db_status") or {}

    print(f"\nProcessed findings: {processed_findings}")
    print(f"Findings with valid MITRE IDs: {findings_with_valid_ids}")
    if db_status:
        print(
            "Vector DB readiness: "
            f"{db_status.get('reason', 'UNKNOWN')} "
            f"(ready={db_status.get('ready', False)}, "
            f"collection={db_status.get('collection', 'unknown')}, "
            f"vectors={db_status.get('vector_count', 0)})"
        )
    print(f"\n--- Sample results ({min(n, len(mapped))} of {len(mapped)} mapped findings) ---")
    for finding in mapped[:n]:
        meta = finding["metadata"]
        mapping = meta["mitre_mapping"]
        print(f"\n  Title:   {finding.get('title', 'N/A')[:80]}")
        print(f"  Summary: {meta.get('technical_summary', 'N/A')[:100]}")
        print(f"  MITRE:   {', '.join(mapping['mitre_ids']) or 'none'}")
        print(f"  Valid:   {mapping.get('validation_passed', 'N/A')}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    routing_mode = "local"
    output_dir = None
    max_findings = None
    batch_mode = False
    positional_arg = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--routing-mode" and i + 1 < len(args):
            routing_mode = args[i + 1]
            i += 2
        elif args[i] == "--output-dir" and i + 1 < len(args):
            output_dir = Path(args[i + 1])
            i += 2
        elif args[i] == "--max-findings" and i + 1 < len(args):
            max_findings = int(args[i + 1])
            i += 2
        elif args[i] == "--batch":
            batch_mode = True
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                positional_arg = args[i + 1]
                i += 2
            else:
                i += 1
        else:
            positional_arg = args[i]
            i += 1

    if not positional_arg:
        print("Error: provide a JSON file path or --batch <directory>")
        sys.exit(1)

    if output_dir is None:
        output_dir = Path("data/mapped")

    if batch_mode:
        input_dir = Path(positional_arg)
        if not input_dir.is_dir():
            print(f"Directory not found: {input_dir}")
            sys.exit(1)

        json_files = sorted(input_dir.glob("*.json"))
        if not json_files:
            print(f"No JSON files found in {input_dir}")
            sys.exit(1)

        print(f"Batch mode: {len(json_files)} files in {input_dir}")
        success = all(
            run_pipeline(jf, output_dir, routing_mode, max_findings)
            for jf in json_files
        )
        sys.exit(0 if success else 1)
    else:
        success = run_pipeline(Path(positional_arg), output_dir, routing_mode, max_findings)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
