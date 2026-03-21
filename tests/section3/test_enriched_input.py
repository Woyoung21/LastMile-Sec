"""Enriched JSON loading (minimal packet shape)."""

from __future__ import annotations

import json
from pathlib import Path

from src.section3_rag_correlation.correlation.enriched_input import iter_enriched_findings


def test_iter_enriched_findings_skips_incomplete(tmp_path: Path) -> None:
    p = tmp_path / "packet.json"
    p.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "a",
                        "metadata": {
                            "technical_summary": "Summary one",
                            "mitre_mapping": {"mitre_ids": ["T1110"]},
                        },
                    },
                    {"id": "b", "metadata": {}},
                    {
                        "id": "c",
                        "metadata": {
                            "technical_summary": "No mitre",
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    out = list(iter_enriched_findings(p))
    assert len(out) == 1
    ef, raw = out[0]
    assert ef.finding_id == "a"
    assert ef.mitre_ids == ["T1110"]
    assert ef.technical_summary == "Summary one"
    assert raw["id"] == "a"
    assert raw["metadata"]["technical_summary"] == "Summary one"
