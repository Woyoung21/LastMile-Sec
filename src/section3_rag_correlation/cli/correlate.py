"""Correlate enriched findings (data/mapped) using native Cypher three-way filter."""

from __future__ import annotations

import argparse
import json
from copy import copy
from datetime import date, datetime
from pathlib import Path
from typing import Any

from src.section3_rag_correlation import config
from src.section3_rag_correlation.correlation.enriched_input import (
    iter_all_mapped_json,
    iter_enriched_findings_from_data,
    load_mapped_packet,
)
from src.section3_rag_correlation.correlation.three_way_filter import (
    CandidateControl,
    correlate_finding,
    normalized_tech_stack,
)
from src.section3_rag_correlation.graph.neo4j_client import get_driver


def _json_safe(value: Any) -> Any:
    """Make Neo4j driver values (e.g. DateTime) and nested structures JSON-serializable."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    mod = getattr(type(value), "__module__", "")
    if mod.startswith("neo4j."):
        if hasattr(value, "iso_format"):
            return value.iso_format()
        return str(value)
    return str(value)


def _best_control_for_output(control: dict[str, Any] | None) -> dict[str, Any] | None:
    """Copy of Neo4j control node dict: strip embedding, JSON-safe property values."""
    if control is None:
        return None
    c = copy(control)
    c.pop("remediation_embedding", None)
    return _json_safe(c)


def _candidate_to_dict(cand: CandidateControl) -> dict[str, Any]:
    """Serialize one candidate for JSON output."""
    vendor_name = None
    if cand.vendor:
        vendor_name = cand.vendor.get("name")
    return {
        "vector_similarity": cand.vector_similarity,
        "composite_score": cand.composite_score,
        "mitre_matched": cand.mitre_matched,
        "vendor_matched": cand.vendor_matched,
        "matched_mitre_ids": cand.matched_mitre,
        "vendor_name": vendor_name,
        "control": _best_control_for_output(cand.control),
    }


def _write_correlated_packet(input_path: Path, data: dict[str, Any]) -> Path:
    config.ensure_correlated_dir()
    out_path = config.CORRELATED_JSON_DIR / f"{input_path.stem}_correlated.json"
    with out_path.open("w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)
        fp.write("\n")
    return out_path


def run_correlate(
    json_path: Path | None = None,
    mapped_dir: Path | None = None,
    max_findings: int | None = None,
    tech_stack: str | None = None,
) -> None:
    driver = get_driver()
    try:
        ts = None
        if tech_stack:
            ts = normalized_tech_stack([x.strip() for x in tech_stack.split(",")])

        paths: list[Path] = []
        if json_path:
            paths = [json_path]
        else:
            d = mapped_dir or config.ENRICHED_JSON_DIR
            paths = list(iter_all_mapped_json(d))

        if not paths:
            print(f"No JSON files to process under {mapped_dir or json_path}")
            return

        n = 0
        for jp in paths:
            jp = jp.resolve()
            data = load_mapped_packet(jp)
            for finding, raw in iter_enriched_findings_from_data(data, jp):
                if max_findings is not None and n >= max_findings:
                    _write_correlated_packet(jp, data)
                    print("max_findings reached.")
                    return

                result = correlate_finding(driver, finding, tech_stack=ts)
                meta = raw.setdefault("metadata", {})

                best = result.best
                best_vendor = None
                best_score = None
                if best:
                    if best.vendor:
                        best_vendor = best.vendor.get("name")
                    best_score = best.composite_score

                _FRAMEWORK_VENDOR = "NIST SP 800-53"
                vendor_cands = [
                    c for c in result.candidates
                    if c.vendor and c.vendor.get("name") != _FRAMEWORK_VENDOR
                ]
                framework_cands = [
                    c for c in result.candidates
                    if not c.vendor or c.vendor.get("name") == _FRAMEWORK_VENDOR
                ]

                meta["rag_correlation"] = {
                    "similarity_score": result.similarity,
                    "composite_score": best_score,
                    "vendor_name": best_vendor,
                    "best_control": _best_control_for_output(result.control),
                    "mitre_matched": best.mitre_matched if best else False,
                    "vendor_matched": best.vendor_matched if best else False,
                    "vendor_controls": [_candidate_to_dict(c) for c in vendor_cands],
                    "framework_controls": [_candidate_to_dict(c) for c in framework_cands],
                }

                score_part = (
                    f"{best_score:.2f}" if best_score is not None else "n/a"
                )
                v_disp = best_vendor if best_vendor else "—"
                flags = []
                if best and best.mitre_matched:
                    flags.append("MITRE")
                if best and best.vendor_matched:
                    flags.append("vendor")
                flag_str = f" [{'+'.join(flags)}]" if flags else ""
                print(
                    f"[OK] Correlated {finding.finding_id} -> {v_disp} (Score: {score_part}{flag_str})"
                )
                n += 1

            _write_correlated_packet(jp, data)
    finally:
        driver.close()


def main() -> None:
    p = argparse.ArgumentParser(description="Section 3 three-way correlation (Neo4j)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--json", type=Path, default=None, help="Single mapped JSON file")
    g.add_argument(
        "--dir",
        type=Path,
        default=None,
        help="Directory of mapped JSON (default: ENRICHED_JSON_DIR)",
    )
    p.add_argument("--max-findings", type=int, default=None)
    p.add_argument(
        "--tech-stack",
        type=str,
        default=None,
        help="Override GLOBAL_TECH_STACK (comma-separated)",
    )
    args = p.parse_args()
    run_correlate(
        json_path=args.json,
        mapped_dir=args.dir,
        max_findings=args.max_findings,
        tech_stack=args.tech_stack,
    )


if __name__ == "__main__":
    main()
