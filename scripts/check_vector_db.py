#!/usr/bin/env python3
"""Check Actian VectorAI collection readiness for Section 2 mapper."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.section2_report_map.config import ATTACKMapperConfig
from src.section2_report_map.mapper import ActianVectorAIDBClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", default=ATTACKMapperConfig.VECTOR_DB_ADDRESS)
    parser.add_argument("--collection", default=ATTACKMapperConfig.VECTOR_DB_COLLECTION)
    parser.add_argument("--expected-dim", type=int, default=ATTACKMapperConfig.EXPECTED_EMBEDDING_DIM)
    parser.add_argument("--min-vectors", type=int, default=ATTACKMapperConfig.MIN_COLLECTION_VECTORS)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    client = ActianVectorAIDBClient(address=args.address)
    status = client.check_collection_ready(
        collection_name=args.collection,
        expected_dim=args.expected_dim,
        min_vectors=args.min_vectors,
    )

    if args.as_json:
        print(json.dumps(status.model_dump(), indent=2))
    else:
        print(
            "Vector DB readiness: "
            f"ready={status.ready}, reason={status.reason}, "
            f"address={status.address}, collection={status.collection}, "
            f"vector_count={status.vector_count}, probe_ok={status.probe_ok}"
        )

    return 0 if status.ready else 2


if __name__ == "__main__":
    sys.exit(main())
