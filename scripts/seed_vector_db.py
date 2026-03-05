#!/usr/bin/env python3
"""Seed Actian VectorAI MITRE collection from ATT&CK corpus + mapped findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.section2_report_map.config import ATTACKMapperConfig

TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _normalize_summary(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def _normalize_mitre_ids(mitre_ids: list[Any]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for item in mitre_ids:
        value = str(item or "").strip().upper()
        if not value or value in seen:
            continue
        if TECHNIQUE_ID_PATTERN.match(value):
            seen.add(value)
            normalized.append(value)
    return normalized


def parse_attack_corpus(attack_corpus_path: Path) -> list[dict[str, Any]]:
    with open(attack_corpus_path, "r", encoding="utf-8") as handle:
        bundle = json.load(handle)

    records: list[dict[str, Any]] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") != "mitre-attack":
                continue
            candidate = str(ref.get("external_id", "")).strip().upper()
            if TECHNIQUE_ID_PATTERN.match(candidate):
                technique_id = candidate
                break

        if not technique_id:
            continue

        technical_summary = _normalize_summary(obj.get("description") or obj.get("name") or "")
        if not technical_summary:
            continue

        payload = {
            "technical_summary": technical_summary,
            "mitre_ids": [technique_id],
            "source": "attack_corpus",
            "name": obj.get("name", ""),
        }
        platforms = obj.get("x_mitre_platforms")
        if platforms:
            payload["platforms"] = platforms

        records.append(payload)

    return records


def parse_mapped_findings(mapped_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for json_file in sorted(mapped_dir.glob("*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as handle:
                packet = json.load(handle)
        except Exception:
            continue

        for finding in packet.get("findings", []):
            metadata = finding.get("metadata") or {}
            mapping = metadata.get("mitre_mapping") or {}
            mitre_ids = _normalize_mitre_ids(mapping.get("mitre_ids") or [])
            if not mitre_ids:
                continue

            technical_summary = _normalize_summary(metadata.get("technical_summary") or "")
            if not technical_summary:
                continue

            records.append(
                {
                    "technical_summary": technical_summary,
                    "mitre_ids": mitre_ids,
                    "source": "local_mapped",
                    "title": finding.get("title", ""),
                    "source_file": packet.get("source_file", ""),
                }
            )

    return records


def dedupe_seed_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    deduped_by_key: dict[str, dict[str, Any]] = {}

    for record in records:
        technical_summary = _normalize_summary(record.get("technical_summary") or "")
        mitre_ids = _normalize_mitre_ids(record.get("mitre_ids") or [])
        if not technical_summary or not mitre_ids:
            continue

        key_payload = f"{technical_summary}|{'|'.join(sorted(mitre_ids))}"
        key = hashlib.sha256(key_payload.encode("utf-8")).hexdigest()
        normalized = dict(record)
        normalized["technical_summary"] = technical_summary
        normalized["mitre_ids"] = mitre_ids
        existing = deduped_by_key.get(key)
        if existing is None:
            deduped_by_key[key] = normalized
            continue

        # If duplicate content exists, prefer local mapped evidence over corpus text.
        if existing.get("source") != "local_mapped" and normalized.get("source") == "local_mapped":
            deduped_by_key[key] = normalized

    deduped.extend(deduped_by_key.values())
    return deduped


def _seed_collection(
    records: list[dict[str, Any]],
    address: str,
    collection: str,
    recreate: bool,
    batch_size: int,
) -> int:
    from sentence_transformers import SentenceTransformer
    from cortex import CortexClient, DistanceMetric

    if not records:
        return 0

    embedder = SentenceTransformer(ATTACKMapperConfig.EMBEDDING_MODEL)
    summaries = [record["technical_summary"] for record in records]
    embeddings = embedder.encode(summaries)

    if hasattr(embeddings, "tolist"):
        embeddings = embeddings.tolist()
    embeddings = [list(vector) for vector in embeddings]
    embedding_dim = len(embeddings[0])

    client = CortexClient(address=address)
    try:
        client.connect()

        if recreate:
            try:
                client.delete_collection(collection)
            except Exception:
                pass

        if not client.has_collection(collection):
            client.create_collection(
                name=collection,
                dimension=embedding_dim,
                distance_metric=DistanceMetric.COSINE,
            )
        else:
            client.open_collection(collection)

        for start in range(0, len(records), batch_size):
            end = min(start + batch_size, len(records))
            batch_ids = list(range(start + 1, end + 1))
            batch_vectors = embeddings[start:end]
            batch_payloads = records[start:end]
            client.batch_upsert(
                collection_name=collection,
                ids=batch_ids,
                vectors=batch_vectors,
                payloads=batch_payloads,
            )

        return int(client.get_vector_count(collection) or 0)
    finally:
        try:
            client.close()
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attack-corpus", type=Path, default=ATTACKMapperConfig.DEFAULT_ATTACK_CORPUS_PATH)
    parser.add_argument("--mapped-dir", type=Path, default=Path("data/mapped"))
    parser.add_argument("--address", default=ATTACKMapperConfig.VECTOR_DB_ADDRESS)
    parser.add_argument("--collection", default=ATTACKMapperConfig.VECTOR_DB_COLLECTION)
    parser.add_argument("--recreate", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--batch-size", type=int, default=128)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.attack_corpus.exists():
        print(f"Error: ATT&CK corpus file not found: {args.attack_corpus}")
        return 1

    if not args.mapped_dir.exists():
        print(f"Error: mapped directory not found: {args.mapped_dir}")
        return 1

    corpus_records = parse_attack_corpus(args.attack_corpus)
    mapped_records = parse_mapped_findings(args.mapped_dir)
    merged_records = corpus_records + mapped_records
    deduped_records = dedupe_seed_records(merged_records)

    print("Seed summary")
    print(f"  Parsed corpus rows: {len(corpus_records)}")
    print(f"  Parsed mapped rows: {len(mapped_records)}")
    print(f"  Merged rows: {len(merged_records)}")
    print(f"  Deduped rows: {len(deduped_records)}")

    if args.dry_run:
        print("  Dry run: no vectors written")
        return 0

    final_count = _seed_collection(
        records=deduped_records,
        address=args.address,
        collection=args.collection,
        recreate=args.recreate,
        batch_size=max(1, args.batch_size),
    )
    print(f"  Inserted rows: {len(deduped_records)}")
    print(f"  Final vector count: {final_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
