"""Load Section 2 mapped JSON packets from data/mapped (or ENRICHED_JSON_DIR)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


@dataclass
class EnrichedFinding:
    """Minimal fields for correlation."""

    packet_source: Path
    finding_id: str
    technical_summary: str
    mitre_ids: list[str]


def _mitre_ids_from_finding(f: dict[str, Any]) -> list[str]:
    meta = f.get("metadata") or {}
    mm = meta.get("mitre_mapping") or {}
    raw = mm.get("mitre_ids") or []
    out = []
    for x in raw:
        if isinstance(x, str) and x.strip():
            out.append(x.strip())
    return out


def load_mapped_packet(json_path: Path) -> dict[str, Any]:
    """Load full mapped packet JSON (single read)."""
    return json.loads(json_path.read_text(encoding="utf-8"))


def iter_enriched_findings_from_data(
    data: dict[str, Any],
    json_path: Path,
) -> Iterator[tuple[EnrichedFinding, dict[str, Any]]]:
    """Yield (EnrichedFinding, raw finding dict) for correlatable findings only."""
    for f in data.get("findings") or []:
        if not isinstance(f, dict):
            continue
        meta = f.get("metadata") or {}
        ts = meta.get("technical_summary")
        mids = _mitre_ids_from_finding(f)
        if not ts or not isinstance(ts, str) or not ts.strip():
            continue
        if not mids:
            continue
        fid = str(f.get("id") or "")
        yield (
            EnrichedFinding(
                packet_source=json_path,
                finding_id=fid,
                technical_summary=ts.strip(),
                mitre_ids=mids,
            ),
            f,
        )


def iter_enriched_findings(
    json_path: Path,
) -> Iterator[tuple[EnrichedFinding, dict[str, Any]]]:
    """Yield findings that have both technical_summary and mitre_ids (with raw dict for mutation)."""
    data = load_mapped_packet(json_path)
    yield from iter_enriched_findings_from_data(data, json_path)


def iter_all_mapped_json(dir_path: Path) -> Iterator[Path]:
    """All *_mapped_*.json or *.json under dir (non-recursive)."""
    if not dir_path.is_dir():
        return
    for p in sorted(dir_path.glob("*.json")):
        if p.is_file():
            yield p
