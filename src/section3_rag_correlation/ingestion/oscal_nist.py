"""Parse NIST OSCAL catalog JSON into SecurityControl; load MITRE NIST↔ATT&CK mapping.

Guardrails: padded join keys for MITRE dict, NIST- prefixed control_id for MERGE,
sanitized prose (no raw OSCAL {{ insert: param }}), vendor_product = NIST SP 800-53.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

from src.section3_rag_correlation.schemas import SecurityControl

# OSCAL control id: family-number, optional enhancement .n
_CONTROL_ID_RE = re.compile(r"^([A-Za-z]{2,4})-(\d+)(?:\.(\d+))?$")

# {{ insert: param, ... }} and any remaining {{ ... }} blocks
_OSCAL_INSERT_PARAM = re.compile(
    r"\{\{\s*insert:\s*param\s*,\s*[^}]+\}\}",
    re.IGNORECASE,
)
_OSCAL_ANY_BRACE = re.compile(r"\{\{[^}]+\}\}")

VENDOR_NIST_800_53 = "NIST SP 800-53"


def normalize_nist_control_id(raw: str) -> str:
    """Canonical join key: padded uppercase family-number (e.g. ac-1 -> AC-01, AC-02 -> AC-02).

    Used for both OSCAL ``control.id`` and MITRE mapping ``capability_id`` so lookups align.
    """
    s = raw.strip().upper().replace(" ", "")
    m = _CONTROL_ID_RE.match(s)
    if not m:
        return s
    fam, main, enh = m.group(1), int(m.group(2)), m.group(3)
    main_s = str(main).zfill(2)
    if enh:
        return f"{fam}-{main_s}.{enh}"
    return f"{fam}-{main_s}"


def nist_prefixed_control_id(join_key: str) -> str:
    """Neo4j MERGE key for NIST-ingested controls (avoids collision with STIG/other AC-xx ids)."""
    return f"NIST-{join_key}"


def sanitize_oscal_prose(text: str) -> str:
    """Remove OSCAL parameter placeholders; do not pass raw ``{{ ... }}`` to embeddings."""
    if not text or not text.strip():
        return ""
    t = _OSCAL_INSERT_PARAM.sub("[ASSIGNMENT]", text)
    t = _OSCAL_ANY_BRACE.sub("[ASSIGNMENT]", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def collect_prose_recursive(obj: Any) -> list[str]:
    """Gather all ``prose`` strings from nested OSCAL parts."""
    out: list[str] = []
    if isinstance(obj, dict):
        p = obj.get("prose")
        if isinstance(p, str) and p.strip():
            out.append(p)
        for k, v in obj.items():
            if k == "prose":
                continue
            if isinstance(v, (dict, list)):
                out.extend(collect_prose_recursive(v))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(collect_prose_recursive(item))
    return out


def build_remediation_text(control: dict[str, Any]) -> str:
    """Title + concatenated sanitized prose from control parts."""
    title = (control.get("title") or "").strip()
    parts = control.get("parts") or []
    raw_lines = collect_prose_recursive(parts)
    body = sanitize_oscal_prose("\n\n".join(raw_lines))
    if title and body:
        return f"{title}\n\n{body}"
    if title:
        return title
    return body


def load_attack_mapping(path: Path | str) -> dict[str, list[str]]:
    """Load MITRE mapping JSON; keys are join keys (no NIST- prefix), values sorted technique ids."""
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    mapping_objects = data.get("mapping_objects") or []
    acc: dict[str, set[str]] = defaultdict(set)
    for row in mapping_objects:
        if row.get("mapping_type") != "mitigates":
            continue
        cap = row.get("capability_id")
        tid = row.get("attack_object_id")
        if not cap or not tid:
            continue
        key = normalize_nist_control_id(str(cap))
        acc[key].add(str(tid).strip())
    return {k: sorted(v) for k, v in acc.items()}


def _iter_controls_nested(control: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield control
    for child in control.get("controls") or []:
        if isinstance(child, dict):
            yield from _iter_controls_nested(child)


def iter_controls_from_catalog(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield each control dict from ``catalog.groups[].controls`` (including nested enhancements)."""
    catalog = data.get("catalog") or {}
    for group in catalog.get("groups") or []:
        for c in group.get("controls") or []:
            if isinstance(c, dict):
                yield from _iter_controls_nested(c)


def load_oscal_catalog(path: Path | str) -> dict[str, Any]:
    """Load full OSCAL JSON (stdlib; large files may be memory-heavy)."""
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))


def oscal_control_to_security_control(
    raw: dict[str, Any],
    mitre_by_join_key: dict[str, list[str]],
) -> SecurityControl | None:
    """Build SecurityControl from one OSCAL control dict; return None if nothing to embed."""
    cid = raw.get("id")
    if not cid or not isinstance(cid, str):
        return None
    join_key = normalize_nist_control_id(cid.strip())
    remediation = build_remediation_text(raw)
    if not remediation.strip():
        return None
    mitre = mitre_by_join_key.get(join_key)
    return SecurityControl(
        control_id=nist_prefixed_control_id(join_key),
        vendor_product=VENDOR_NIST_800_53,
        remediation_steps=remediation,
        mitre_mapping=mitre if mitre else None,
        audit_procedure=None,
    )
