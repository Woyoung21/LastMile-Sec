#!/usr/bin/env python3
"""
LastMile-Sec - full pipeline orchestrator (Sections 1-4)

Runs the existing CLIs in order via subprocess (no changes to underlying scripts):
  1. Section 1: ``python run.py <raw> --pdf-parser langextract``
  2. Section 2: ``python run_section2.py <processed.json>``
  3. Section 3: ``python -m src.section3_rag_correlation.cli.correlate --json <mapped>`` (Neo4j must already be populated)
  4. Section 4: ``python -m src.section4_remediation.cli.remediate --json <correlated>`` (LLM-as-judge enabled; never ``--skip-llm-judge``)

Prerequisites
-------------
- ``GOOGLE_API_KEY`` for Gemini (Section 1 LangExtract PDF, Section 2, Section 4).
- Neo4j reachable with the same settings as the correlate CLI; graph already ingested.
- Vector DB / mapper readiness per project README (Section 2).

On failure, prints which stage failed and exits with the subprocess exit code (or 1).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent

_SAVED_TO_RE = re.compile(r"^Saved to:\s*(.+?)\s*$", re.MULTILINE)
_PIPELINE_OUT_RE = re.compile(
    r"^Pipeline complete\.\s*Output:\s*(.+?)\s*$", re.MULTILINE
)


def _py() -> str:
    return sys.executable


def _subprocess_env() -> dict[str, str]:
    """Environment for child Python processes (Windows-safe Unicode to captured pipes)."""
    env = os.environ.copy()
    # Without this, Section 2 Reporter can raise UnicodeEncodeError when printing Gemini
    # output or scanner text to stdout under cp1252.
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    return env


def _run_step(
    name: str,
    argv: list[str],
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess from repo root; return completed process (stdout/stderr captured)."""
    return subprocess.run(
        argv,
        cwd=_REPO_ROOT,
        env=_subprocess_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _emit_and_parse_saved_to(proc: subprocess.CompletedProcess[str]) -> Path | None:
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    m = _SAVED_TO_RE.search(proc.stdout or "")
    if not m:
        return None
    return Path(m.group(1).strip()).resolve()


def _emit_and_parse_pipeline_output(proc: subprocess.CompletedProcess[str]) -> Path | None:
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    m = _PIPELINE_OUT_RE.search(proc.stdout or "")
    if not m:
        return None
    return Path(m.group(1).strip()).resolve()


def _correlated_path_for_mapped(mapped_path: Path) -> Path:
    """Match ``_write_correlated_packet`` in correlate CLI (same default dir as Section 3 config)."""
    correlated_dir = (_REPO_ROOT / os.environ.get("CORRELATED_JSON_DIR", "data/correlate")).resolve()
    stem = mapped_path.stem
    return correlated_dir / f"{stem}_correlated.json"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Sections 1-4 in sequence (subprocess; Neo4j must be pre-populated).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "raw_path",
        type=Path,
        help="Path to raw input (CSV, PCAP, PDF, etc.) for Section 1",
    )
    parser.add_argument(
        "--routing-mode",
        choices=["local", "cloud"],
        default="local",
        help="Section 2 mapper routing (default: local)",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Forwarded to Section 2, 3, and 4 when set",
    )
    parser.add_argument(
        "--tech-stack",
        type=str,
        default=None,
        help="Comma-separated; forwarded to correlate and remediate",
    )
    parser.add_argument(
        "--enable-search-augmentation",
        action="store_true",
        help="Forwarded to Section 4 remediate only",
    )

    args = parser.parse_args()
    raw_path = args.raw_path.resolve()
    if not raw_path.is_file():
        print(f"Error: file not found: {raw_path}", file=sys.stderr)
        sys.exit(1)

    # --- Section 1 ---
    s1_argv = [
        _py(),
        str(_REPO_ROOT / "run.py"),
        str(raw_path),
        "--pdf-parser",
        "langextract",
    ]
    print(f"\n{'=' * 60}\n  Pipeline: Section 1 (run.py, langextract)\n{'=' * 60}\n")
    p1 = _run_step("Section 1", s1_argv)
    if p1.returncode != 0:
        print(f"\n[Pipeline] Section 1 failed (exit {p1.returncode}).", file=sys.stderr)
        sys.exit(p1.returncode if p1.returncode else 1)
    processed = _emit_and_parse_saved_to(p1)
    if not processed or not processed.is_file():
        print(
            "\n[Pipeline] Could not parse Section 1 output path from stdout "
            "(expected 'Saved to: <path>').",
            file=sys.stderr,
        )
        sys.exit(1)

    # --- Section 2 ---
    s2_argv = [
        _py(),
        str(_REPO_ROOT / "run_section2.py"),
        str(processed),
        "--routing-mode",
        args.routing_mode,
    ]
    if args.max_findings is not None:
        s2_argv.extend(["--max-findings", str(args.max_findings)])

    print(f"\n{'=' * 60}\n  Pipeline: Section 2 (run_section2.py)\n{'=' * 60}\n")
    p2 = _run_step("Section 2", s2_argv)
    if p2.returncode != 0:
        print(f"\n[Pipeline] Section 2 failed (exit {p2.returncode}).", file=sys.stderr)
        sys.exit(p2.returncode if p2.returncode else 1)
    mapped = _emit_and_parse_pipeline_output(p2)
    if not mapped or not mapped.is_file():
        print(
            "\n[Pipeline] Could not parse Section 2 output path from stdout "
            "(expected 'Pipeline complete. Output: <path>').",
            file=sys.stderr,
        )
        sys.exit(1)

    # --- Section 3 (correlate only) ---
    s3_argv = [
        _py(),
        "-m",
        "src.section3_rag_correlation.cli.correlate",
        "--json",
        str(mapped),
    ]
    if args.max_findings is not None:
        s3_argv.extend(["--max-findings", str(args.max_findings)])
    if args.tech_stack:
        s3_argv.extend(["--tech-stack", args.tech_stack])

    print(f"\n{'=' * 60}\n  Pipeline: Section 3 (correlate)\n{'=' * 60}\n")
    p3 = _run_step("Section 3", s3_argv)
    if p3.returncode != 0:
        print(f"\n[Pipeline] Section 3 failed (exit {p3.returncode}).", file=sys.stderr)
        sys.exit(p3.returncode if p3.returncode else 1)
    if p3.stdout:
        print(p3.stdout, end="")
    if p3.stderr:
        print(p3.stderr, end="", file=sys.stderr)

    correlated = _correlated_path_for_mapped(mapped)
    if not correlated.is_file():
        print(
            f"\n[Pipeline] Expected correlated file not found: {correlated}",
            file=sys.stderr,
        )
        sys.exit(1)

    # --- Section 4 (full LLM-as-judge; never --skip-llm-judge) ---
    s4_argv = [
        _py(),
        "-m",
        "src.section4_remediation.cli.remediate",
        "--json",
        str(correlated),
    ]
    if args.max_findings is not None:
        s4_argv.extend(["--max-findings", str(args.max_findings)])
    if args.tech_stack:
        s4_argv.extend(["--tech-stack", args.tech_stack])
    if args.enable_search_augmentation:
        s4_argv.append("--enable-search-augmentation")

    print(f"\n{'=' * 60}\n  Pipeline: Section 4 (remediate)\n{'=' * 60}\n")
    p4 = _run_step("Section 4", s4_argv)
    if p4.stdout:
        print(p4.stdout, end="")
    if p4.stderr:
        print(p4.stderr, end="", file=sys.stderr)
    if p4.returncode != 0:
        print(f"\n[Pipeline] Section 4 failed (exit {p4.returncode}).", file=sys.stderr)
        sys.exit(p4.returncode if p4.returncode else 1)

    print(f"\n{'=' * 60}\n  Pipeline finished successfully.\n{'=' * 60}\n")


if __name__ == "__main__":
    main()
