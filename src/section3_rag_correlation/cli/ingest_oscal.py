"""Ingest NIST OSCAL catalog JSON: deterministic controls → embed → MERGE into Neo4j."""

from __future__ import annotations

import argparse
import traceback
from pathlib import Path

from src.section3_rag_correlation import config
from src.section3_rag_correlation.graph.merge_controls import merge_security_control
from src.section3_rag_correlation.graph.neo4j_client import apply_schema, get_driver
from src.section3_rag_correlation.ingestion.oscal_nist import (
    iter_controls_from_catalog,
    load_attack_mapping,
    load_oscal_catalog,
    normalize_nist_control_id,
    oscal_control_to_security_control,
)
from src.section3_rag_correlation.ingestion.progress import (
    OscalProgressEntry,
    append_oscal_progress,
    load_completed_oscal_join_keys,
)
from src.section3_rag_correlation.llm import get_embeddings


def run_ingest_oscal(
    oscal_catalog: Path,
    attack_mapping: Path | None = None,
    apply_graph_schema: bool = True,
    limit_controls: int | None = None,
    log_path: Path | None = None,
) -> None:
    catalog_path = oscal_catalog.resolve()
    if not catalog_path.is_file():
        print(f"OSCAL catalog not found: {catalog_path}")
        return

    config.ensure_log_dir()
    log = log_path or config.PROCESSED_OSCAL_LOG
    log_key = str(catalog_path)

    mitre_by_key: dict[str, list[str]] = {}
    if attack_mapping is not None:
        am = attack_mapping.resolve()
        if not am.is_file():
            print(f"Attack mapping not found: {am}")
            return
        print(f"Loading MITRE mapping from {am.name}...")
        mitre_by_key = load_attack_mapping(am)
        print(f"  {len(mitre_by_key)} control keys with mitigates entries")

    print(f"Loading OSCAL catalog {catalog_path.name}...")
    data = load_oscal_catalog(catalog_path)

    driver = get_driver()
    if apply_graph_schema:
        print("Applying Neo4j schema (constraints + vector index)...")
        apply_schema(driver)

    embedder = get_embeddings()
    done_keys = load_completed_oscal_join_keys(log, catalog_path)

    merged = 0
    try:
        for raw in iter_controls_from_catalog(data):
            join_key = normalize_nist_control_id(str(raw.get("id") or ""))
            if not join_key:
                continue
            if join_key in done_keys:
                continue

            ctrl = oscal_control_to_security_control(raw, mitre_by_key)
            if ctrl is None:
                append_oscal_progress(
                    log,
                    OscalProgressEntry(
                        catalog_path=log_key,
                        join_key=join_key,
                        status="skipped",
                        detail="no prose after parse",
                    ),
                )
                done_keys.add(join_key)
                continue

            if limit_controls is not None and merged >= limit_controls:
                print(
                    f"Stopped after {limit_controls} merged control(s) (--limit-controls). "
                    "Run without --limit-controls for a full ingest."
                )
                print("OSCAL ingest finished.")
                return

            print(f"Merging {ctrl.control_id!r} (join_key={join_key})...")
            try:
                emb = embedder.embed_documents([ctrl.remediation_steps])[0]
                if len(emb) != config.EMBEDDING_DIMENSIONS:
                    raise ValueError(
                        f"embedding dim {len(emb)} != {config.EMBEDDING_DIMENSIONS}"
                    )
                merge_security_control(driver, ctrl, emb)
                append_oscal_progress(
                    log,
                    OscalProgressEntry(
                        catalog_path=log_key,
                        join_key=join_key,
                        status="ok",
                        detail=None,
                    ),
                )
                done_keys.add(join_key)
                merged += 1
                print(f"  ok ({merged})")
            except Exception as e:
                print(f"  error: {e}")
                traceback.print_exc()
                append_oscal_progress(
                    log,
                    OscalProgressEntry(
                        catalog_path=log_key,
                        join_key=join_key,
                        status="error",
                        detail=str(e),
                    ),
                )
    finally:
        driver.close()

    print("OSCAL ingest finished.")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Section 3 NIST OSCAL JSON → Neo4j ingest (no LLM extraction)"
    )
    p.add_argument(
        "--oscal-catalog",
        type=Path,
        required=True,
        help="Path to NIST OSCAL catalog JSON (full catalog or resolved baseline profile)",
    )
    p.add_argument(
        "--attack-mapping",
        type=Path,
        default=None,
        help="Optional MITRE NIST↔ATT&CK mapping JSON (e.g. nist_800_53-rev5_attack-16.1-enterprise_json.json)",
    )
    p.add_argument(
        "--no-schema",
        action="store_true",
        help="Do not run schema.cypher (constraints + vector index)",
    )
    p.add_argument(
        "--limit-controls",
        type=int,
        default=None,
        help="Merge at most N controls (smoke test)",
    )
    p.add_argument(
        "--log",
        type=Path,
        default=None,
        help=f"Progress log path (default: {config.PROCESSED_OSCAL_LOG})",
    )
    args = p.parse_args()
    run_ingest_oscal(
        oscal_catalog=args.oscal_catalog,
        attack_mapping=args.attack_mapping,
        apply_graph_schema=not args.no_schema,
        limit_controls=args.limit_controls,
        log_path=args.log,
    )


if __name__ == "__main__":
    main()
