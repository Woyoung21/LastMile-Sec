"""Section 4 CLI: generate verified remediation from correlated findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.section4_remediation import config
from src.section4_remediation.generator import build_remediation_metadata
from src.section4_remediation.selfrag import generate_with_verification


def _iter_correlated_json(dir_path: Path) -> list[Path]:
    if not dir_path.is_dir():
        return []
    return sorted(p for p in dir_path.glob("*_correlated.json") if p.is_file())


def _iter_findings_with_correlation(
    data: dict[str, Any],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Yield (finding_dict, rag_correlation_dict) for findings that have correlation."""
    results = []
    for f in data.get("findings") or []:
        if not isinstance(f, dict):
            continue
        meta = f.get("metadata") or {}
        corr = meta.get("rag_correlation")
        if not corr or not isinstance(corr, dict):
            continue
        ts = meta.get("technical_summary")
        if not ts or not isinstance(ts, str) or not ts.strip():
            continue
        results.append((f, corr))
    return results


def _write_remediated(input_path: Path, data: dict[str, Any]) -> Path:
    config.ensure_remediated_dir()
    stem = input_path.stem
    if stem.endswith("_correlated"):
        stem = stem[: -len("_correlated")]
    out_path = config.REMEDIATED_JSON_DIR / f"{stem}_remediated.json"
    with out_path.open("w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)
        fp.write("\n")
    return out_path


def run_remediate(
    json_path: Path | None = None,
    correlated_dir: Path | None = None,
    max_findings: int | None = None,
    tech_stack: str | None = None,
    skip_llm_judge: bool = False,
) -> None:
    ts: list[str] | None = None
    if tech_stack:
        ts = [x.strip() for x in tech_stack.split(",") if x.strip()]

    paths: list[Path] = []
    if json_path:
        paths = [json_path]
    else:
        d = correlated_dir or config.CORRELATED_JSON_DIR
        paths = _iter_correlated_json(d)

    if not paths:
        print(f"No correlated JSON files found under {correlated_dir or config.CORRELATED_JSON_DIR}")
        return

    total_processed = 0

    for jp in paths:
        jp = jp.resolve()
        print(f"\nProcessing {jp.name}")
        with jp.open("r", encoding="utf-8") as fp:
            data = json.load(fp)

        pairs = _iter_findings_with_correlation(data)
        if not pairs:
            print("  No correlatable findings — skipping.")
            continue

        for finding, correlation in pairs:
            if max_findings is not None and total_processed >= max_findings:
                print("  max_findings reached.")
                break

            fid = finding.get("id", "?")
            output, verification = generate_with_verification(
                finding,
                correlation,
                ts,
                use_llm_judge=not skip_llm_judge,
            )

            meta = finding.setdefault("metadata", {})
            meta["remediation"] = build_remediation_metadata(output, verification)

            status = "PASS" if verification.passed else "FAIL"
            n_steps = len(output.steps)
            att = verification.attempts
            g = verification.grounding_score
            r = verification.relevance_score
            print(
                f"  [{status}] {fid} -> {n_steps} steps "
                f"(G:{g:.2f} R:{r:.2f} attempts:{att})"
            )
            total_processed += 1

        out = _write_remediated(jp, data)
        print(f"  Written to {out}")

    print(f"\nDone. {total_processed} findings remediated.")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Section 4: generate verified remediation from correlated findings"
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument(
        "--json", type=Path, default=None,
        help="Single correlated JSON file",
    )
    g.add_argument(
        "--dir", type=Path, default=None,
        help="Directory of correlated JSON (default: CORRELATED_JSON_DIR)",
    )
    p.add_argument("--max-findings", type=int, default=None)
    p.add_argument(
        "--tech-stack", type=str, default=None,
        help="Override GLOBAL_TECH_STACK (comma-separated)",
    )
    p.add_argument(
        "--skip-llm-judge", action="store_true",
        help="Use heuristic grounding only (faster, no extra LLM calls for verification)",
    )
    args = p.parse_args()
    run_remediate(
        json_path=args.json,
        correlated_dir=args.dir,
        max_findings=args.max_findings,
        tech_stack=args.tech_stack,
        skip_llm_judge=args.skip_llm_judge,
    )


if __name__ == "__main__":
    main()
