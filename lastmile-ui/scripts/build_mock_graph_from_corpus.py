"""
Build lastmile-ui/src/data/mockGraphData.json from data/corpus (PDFs + NIST OSCAL JSON).
Run from repo root: python lastmile-ui/scripts/build_mock_graph_from_corpus.py
Or from lastmile-ui: python scripts/build_mock_graph_from_corpus.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS = REPO_ROOT / "data" / "corpus"
OUT = Path(__file__).resolve().parents[1] / "src" / "data" / "mockGraphData.json"

try:
    import fitz  # PyMuPDF
except ImportError as e:
    raise SystemExit("Install PyMuPDF: pip install PyMuPDF") from e

MITRE_POOL = [
    "T1190", "T1059.001", "T1059.004", "T1078", "T1110", "T1021.001", "T1550.001",
    "T1562.001", "T1070.001", "T1486", "T1490", "T1047", "T1547.001", "T1136.001",
    "T1098", "T1530", "T1539", "T1552.001", "T1003.001", "T1213", "T1195.002",
    "T1204.002", "T1566.001", "T1027", "T1036.005", "T1548.002", "T1068", "T1083",
    "T1018", "T1046", "T1090", "T1572", "T1499", "T1484.001", "T1553.004",
    "T1071.001", "T1105", "T1218", "T1219", "T1566.002",
]


def slug_fw(name: str) -> str:
    s = re.sub(r"[^\w]+", "-", name.lower()).strip("-")
    return f"fw-{s[:48]}"


_RE_PAGE = re.compile(r"\bPage\s+\d+\b", re.I)
_RE_TOC_TRAIL = re.compile(r"(?:[.\u00b7…·\-_]\s*){4,}\d+\s*$")
_RE_LEADER_LINE = re.compile(r"^\s*\.{3,}\s*\d+\s*$", re.M)
_RE_FOOTER_LINE = re.compile(
    r"^\s*(Copyright|All rights reserved|CIS Benchmark|DISA|STIG|Benchmark Date|"
    r"This benchmark|National Institute|NIST SP 800)\b.*$",
    re.I | re.M,
)


def clean_extracted_description(text: str) -> str:
    """Strip page noise, TOC leaders, and common PDF footer lines from extracted text."""
    if not text:
        return ""
    t = _RE_FOOTER_LINE.sub(" ", text)
    t = _RE_PAGE.sub(" ", t)
    t = _RE_LEADER_LINE.sub(" ", t)
    t = _RE_TOC_TRAIL.sub("", t)
    t = re.sub(r"\s+Page\s*\d+\s*$", "", t, flags=re.I)
    t = re.sub(r"\s{2,}", " ", t).strip()
    t = re.sub(r"^[\s.:;,_\-–—]+", "", t)
    t = re.sub(r"[\s.:;,_\-–—]+$", "", t)
    return t


def mitre_for_text(text: str, label: str) -> list[str]:
    u = f"{label} {text}".upper()
    pool = set(MITRE_POOL)
    picks: list[str] = []
    if any(k in u for k in ("PASSWORD", "ACCOUNT", "AUTHENTICATION", "MFA", "LOGIN")):
        picks.extend(["T1078", "T1110"])
    if any(k in u for k in ("AUDIT", "LOG", "EVENT", "SIEM")):
        picks.extend(["T1562.001", "T1070.001"])
    if any(k in u for k in ("FIREWALL", "NETWORK", "PORT", "LISTENING")):
        picks.extend(["T1046", "T1090"])
    if any(k in u for k in ("MALWARE", "EXECUTION", "SCRIPT", "POWERSHELL", "BASH")):
        picks.extend(["T1059.001", "T1204.002"])
    if any(k in u for k in ("ENCRYPT", "RANSOM", "CRYPT")):
        picks.append("T1486")
    if any(k in u for k in ("CLOUD", "BUCKET", "S3", "AZURE", "GCP", "IAM")):
        picks.extend(["T1530", "T1550.001"])
    if any(k in u for k in ("REGISTRY", "HKLM", "GPEDIT", "GPO")):
        picks.extend(["T1484.001", "T1547.001"])
    if not picks:
        picks = ["T1078", "T1046"]
    seen: set[str] = set()
    out: list[str] = []
    for p in picks:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= 3:
            break
    i = 0
    while len(out) < 2:
        t = MITRE_POOL[i % len(MITRE_POOL)]
        i += 1
        if t not in seen:
            seen.add(t)
            out.append(t)
    return [x for x in out[:3] if x in pool]


def _pull_section(block: str, title: str) -> str:
    pat = re.compile(
        rf"{title}:\s*(.+?)(?=(?:^(?:Description|Rationale|Audit|Remediation|Profile Applicability|Additional Information):)|\Z)",
        re.S | re.M,
    )
    m = pat.search(block)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1).strip())


def extract_stig_style_blocks(text: str, max_controls: int) -> list[dict]:
    """CIS STIG: '1.10 WN11-00-000040 (Manual)' style section headers."""
    hdr = re.compile(
        r"(?m)^\s*(\d+(?:\.\d+)+)\s+([A-Z][A-Za-z0-9.-]{4,})\s*\((Manual|Automated)\)\s*$",
    )
    matches = list(hdr.finditer(text))
    out: list[dict] = []
    for i, m in enumerate(matches):
        if len(out) >= max_controls:
            break
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]
        desc = _pull_section(block, "Description")
        audit = _pull_section(block, "Audit")
        rem = _pull_section(block, "Remediation")
        rat = _pull_section(block, "Rationale")
        parts = [p for p in (desc, rat, audit, rem) if p and len(p) > 20]
        if not parts:
            continue
        body = clean_extracted_description("\n\n".join(parts))
        if len(body) < 80:
            continue
        sec, rid = m.group(1), m.group(2)
        label = f"{sec}-{rid}"
        out.append({"label": label, "description": body[:2000]})
    return out


def extract_dot_triple_line_style(text: str, max_controls: int) -> list[dict]:
    """Benchmark style: '1.1.1 (L1) Ensure ...' on one line."""
    line_re = re.compile(r"^(\d+\.\d+\.\d+)\s+(.+)$")
    controls: list[dict] = []
    current_id: str | None = None
    buf: list[str] = []

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            if current_id:
                buf.append("")
            continue
        m = line_re.match(line)
        if m:
            if current_id and buf:
                desc = " ".join(x.strip() for x in buf if x.strip())
                desc = re.sub(r"\s+", " ", desc).strip()
                if len(desc) > 50:
                    desc = clean_extracted_description(desc)
                    if len(desc) > 50:
                        controls.append({"label": current_id, "description": desc[:2000]})
                    if len(controls) >= max_controls:
                        return controls[:max_controls]
            current_id = m.group(1)
            buf = [m.group(2).strip()]
        elif current_id:
            if len(line) > 2:
                buf.append(line)

    if current_id and buf and len(controls) < max_controls:
        desc = " ".join(x.strip() for x in buf if x.strip())
        desc = re.sub(r"\s+", " ", desc).strip()
        if len(desc) > 50:
            desc = clean_extracted_description(desc)
            if len(desc) > 50:
                controls.append({"label": current_id, "description": desc[:2000]})

    return controls[:max_controls]


def extract_cis_from_pdf(path: Path, max_controls: int = 14) -> list[dict]:
    doc = fitz.open(path)
    parts: list[str] = []
    for page in doc:
        parts.append(page.get_text())
    doc.close()
    text = "\n".join(parts)

    stig = extract_stig_style_blocks(text, max_controls)
    if len(stig) >= 3:
        return stig[:max_controls]
    dotted = extract_dot_triple_line_style(text, max_controls)
    return (stig + dotted)[:max_controls]


_OSCAL_INSERT = re.compile(r"\{\{\s*insert:\s*param\s*,\s*[^}]+\}\}", re.I)
_OSCAL_ANY = re.compile(r"\{\{[^}]+\}\}")


def sanitize_prose(t: str) -> str:
    if not t:
        return ""
    t = _OSCAL_INSERT.sub("[Assignment: organization-defined value]", t)
    t = _OSCAL_ANY.sub("[Assignment: organization-defined value]", t)
    return re.sub(r"\s+", " ", t).strip()


def collect_prose(obj) -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict):
        p = obj.get("prose")
        if isinstance(p, str) and p.strip():
            out.append(p)
        for k, v in obj.items():
            if k == "prose":
                continue
            if isinstance(v, (dict, list)):
                out.extend(collect_prose(v))
    elif isinstance(obj, list):
        for it in obj:
            out.extend(collect_prose(it))
    return out


def nist_remediation(control: dict) -> str:
    title = (control.get("title") or "").strip()
    parts = control.get("parts") or []
    body = sanitize_prose("\n\n".join(collect_prose(parts)))
    if title and body:
        return f"{title}\n\n{body}"
    return title or body


def iter_nist_controls(data: dict):
    catalog = data.get("catalog") or {}
    for group in catalog.get("groups") or []:
        for c in group.get("controls") or []:
            if isinstance(c, dict):
                yield from _iter_nested(c)


def _iter_nested(control: dict):
    yield control
    for child in control.get("controls") or []:
        if isinstance(child, dict):
            yield from _iter_nested(child)


def normalize_nist_label(cid: str) -> str:
    s = cid.strip().upper().replace(" ", "")
    m = re.match(r"^([A-Z]{2,4})-(\d+)(?:\.(\d+))?$", s)
    if not m:
        return f"NIST-{s}"
    fam, main, enh = m.group(1), int(m.group(2)), m.group(3)
    main_s = str(main).zfill(2)
    if enh:
        return f"NIST-{fam}-{main_s}.{enh}"
    return f"NIST-{fam}-{main_s}"


def extract_nist_from_json(path: Path, max_controls: int = 15) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[dict] = []
    for raw in iter_nist_controls(data):
        cid = raw.get("id")
        if not cid or not isinstance(cid, str):
            continue
        rem = clean_extracted_description(nist_remediation(raw))
        if len(rem) < 80:
            continue
        out.append(
            {
                "label": normalize_nist_label(cid),
                "description": rem[:2000],
            }
        )
        if len(out) >= max_controls:
            break
    return out


def main() -> None:
    nodes: list[dict] = []
    links: list[dict] = []
    pdf_files = sorted(CORPUS.glob("*.pdf"))
    nist_path = CORPUS / "NIST_SP-800-53_rev5_catalog.json"
    if not nist_path.is_file():
        raise SystemExit(f"Missing {nist_path}")

    frameworks: list[tuple[str, str, str]] = []

    # NIST framework
    nist_fw_id = slug_fw("nist-sp-800-53-rev5")
    frameworks.append(
        (
            nist_fw_id,
            "NIST SP 800-53 Rev 5 (OSCAL)",
            "NIST Special Publication 800-53 — security and privacy controls (corpus: NIST_SP-800-53_rev5_catalog.json).",
        )
    )

    for pdf in pdf_files:
        stem = pdf.stem.replace("_", " ")
        fw_id = slug_fw(pdf.stem)
        frameworks.append((fw_id, stem, f"CIS benchmark source: {pdf.name}"))

    for fw_id, label, desc in frameworks:
        nodes.append(
            {"id": fw_id, "group": "Framework", "label": label, "description": desc}
        )

    for mid in MITRE_POOL:
        nodes.append(
            {
                "id": mid,
                "group": "MITRE",
                "label": mid,
                "description": f"MITRE ATT&CK technique {mid} (mapped from control semantics).",
            }
        )

    ctrl_idx = 0
    # NIST controls
    nist_controls = extract_nist_from_json(nist_path, 15)
    nist_fw = frameworks[0][0]
    for c in nist_controls:
        cid = f"ctl-nist-{ctrl_idx}"
        ctrl_idx += 1
        nodes.append(
            {
                "id": cid,
                "group": "Control",
                "label": c["label"],
                "description": c["description"],
            }
        )
        links.append({"source": nist_fw, "target": cid})
        for mid in mitre_for_text(c["description"], c["label"]):
            if any(n["id"] == mid for n in nodes):
                links.append({"source": cid, "target": mid})

    # CIS PDFs
    for pdf in pdf_files:
        fw_id = slug_fw(pdf.stem)
        extracted = extract_cis_from_pdf(pdf, 14)
        for c in extracted:
            cid = f"ctl-{fw_id}-{ctrl_idx}"
            ctrl_idx += 1
            nodes.append(
                {
                    "id": cid,
                    "group": "Control",
                    "label": f"CIS-{c['label']}",
                    "description": c["description"],
                }
            )
            links.append({"source": fw_id, "target": cid})
            for mid in mitre_for_text(c["description"], c["label"]):
                links.append({"source": cid, "target": mid})

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"nodes": nodes, "links": links}, indent=2), encoding="utf-8")
    print(f"Wrote {len(nodes)} nodes, {len(links)} links -> {OUT}")


if __name__ == "__main__":
    main()
