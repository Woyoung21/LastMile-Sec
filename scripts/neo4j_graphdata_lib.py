"""
Shared helpers: Neo4j tabular rows -> lastmile-ui GraphData JSON
(nodes/links compatible with lastmile-ui/src/types/graph.ts).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

# Matches lastmile-ui GraphGroup
GROUP_FRAMEWORK = "Framework"
GROUP_CONTROL = "Control"
GROUP_MITRE = "MITRE"


def slug_fw(name: str) -> str:
    """Stable Framework node id from vendor name."""
    s = re.sub(r"[^\w]+", "-", (name or "unknown").lower()).strip("-")
    return f"fw-{s[:48]}" if s else "fw-unknown"


def control_node_id(vendor: str, cid: str) -> str:
    """Stable unique Control id (vendor + cid may repeat across exports)."""
    key = f"{vendor}\0{cid}".encode("utf-8")
    return "ctl-" + hashlib.sha256(key).hexdigest()[:24]


def _truncate(text: str | None, max_len: int) -> str:
    if not text:
        return ""
    t = str(text).strip()
    if len(t) <= max_len:
        return t
    return t[: max_len - 1].rstrip() + "…"


def _normalize_mitre_ids(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for x in raw:
        if x is None:
            continue
        s = str(x).strip()
        if not s:
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def table_rows_to_graphdata(
    rows: list[dict[str, Any]],
    *,
    max_desc_len: int = 2000,
    framework_description: str | None = None,
) -> dict[str, Any]:
    """
    Build { "nodes": [...], "links": [...] } from export rows.

    Each row should provide vendor, cid, steps, mitre_ids (optional alternate keys below).
    """
    # Accept common Neo4j Browser / script aliases
    def row_vendor(r: dict[str, Any]) -> str:
        return str(r.get("vendor") or r.get("v.name") or "").strip() or "unknown"

    def row_cid(r: dict[str, Any]) -> str:
        return str(r.get("cid") or r.get("c.control_id") or "").strip() or "unknown"

    def row_steps(r: dict[str, Any]) -> str:
        return str(r.get("steps") or r.get("c.remediation_steps") or "")

    def row_mitre(r: dict[str, Any]) -> list[str]:
        return _normalize_mitre_ids(r.get("mitre_ids") or r.get("mids"))

    nodes: list[dict[str, str]] = []
    links: list[dict[str, str]] = []
    fw_ids: set[str] = set()
    ctl_ids_seen: set[str] = set()
    mitre_ids_seen: set[str] = set()
    link_keys: set[str] = set()

    def add_link(src: str, tgt: str) -> None:
        k = f"{src}\0{tgt}"
        if k in link_keys:
            return
        link_keys.add(k)
        links.append({"source": src, "target": tgt})

    for r in rows:
        vendor = row_vendor(r)
        cid = row_cid(r)
        steps = row_steps(r)
        mids = row_mitre(r)

        fw_id = slug_fw(vendor)
        if fw_id not in fw_ids:
            fw_ids.add(fw_id)
            desc = framework_description or f"Vendor / framework: {vendor}"
            nodes.append(
                {
                    "id": fw_id,
                    "group": GROUP_FRAMEWORK,
                    "label": vendor,
                    "description": desc,
                }
            )

        ctl_id = control_node_id(vendor, cid)
        if ctl_id not in ctl_ids_seen:
            ctl_ids_seen.add(ctl_id)
            nodes.append(
                {
                    "id": ctl_id,
                    "group": GROUP_CONTROL,
                    "label": cid,
                    "description": _truncate(steps, max_desc_len),
                }
            )
        add_link(fw_id, ctl_id)

        for mid in mids:
            if mid not in mitre_ids_seen:
                mitre_ids_seen.add(mid)
                nodes.append(
                    {
                        "id": mid,
                        "group": GROUP_MITRE,
                        "label": mid,
                        "description": f"MITRE ATT&CK technique {mid}.",
                    }
                )
            add_link(ctl_id, mid)

    return {"nodes": nodes, "links": links}


def load_rows_from_json_text(text: str) -> list[dict[str, Any]]:
    raw = json.loads(text)
    if not isinstance(raw, list):
        raise ValueError("Expected a JSON array of row objects")
    return [x for x in raw if isinstance(x, dict)]
