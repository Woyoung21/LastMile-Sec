"""
MITRE mapper LoRA training preprocessing (CSC699 v3 notebook).

Keep in sync with gen_v3_notebook.py: the generator embeds this file into the Colab notebook.
Colab instruction template must match AttackMapperPrompts.LOCAL_USER_PROMPT_TEMPLATE in
prompts.py byte-for-byte except for {db_results} and {technical_summary} placeholders.
"""
from __future__ import annotations

import json
import math
import re
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ATTACK_VERSION = "18.1"
ATTACK_BUNDLE: dict[str, Any] = {}
ALLOWLIST: set[str] = set()
DEPRECATION_REMAP: dict[str, str] = {}
EXTRA_DEPRECATION_REMAP: dict[str, str] = {}

# Set by training script before calling normalize_tag_list
MAX_TECHNIQUES_PER_FINDING = 5


def set_max_techniques(n: int) -> None:
    global MAX_TECHNIQUES_PER_FINDING
    MAX_TECHNIQUES_PER_FINDING = n


def load_attack_bundle_raw(corpus_path: str | None) -> str:
    path = Path(corpus_path) if corpus_path else None
    if path and path.is_file():
        return path.read_text(encoding="utf-8")
    url = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
    )
    print("Downloading ATT&CK bundle:", url)
    with urllib.request.urlopen(url, timeout=180) as r:
        return r.read().decode("utf-8")


def allowlist_from_bundle(bundle: dict) -> set[str]:
    allow: set[str] = set()
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        for ext in obj.get("external_references") or []:
            rid = ext.get("external_id") or ""
            if rid.startswith("T") and len(rid) > 1 and rid[1].isdigit():
                allow.add(rid.upper())
    return allow


def deprecation_remap_from_bundle(bundle: dict) -> dict[str, str]:
    stix_to_tid: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        oid = obj.get("id")
        if not oid:
            continue
        for ext in obj.get("external_references") or []:
            rid = ext.get("external_id") or ""
            if rid.startswith("T") and len(rid) > 1 and rid[1].isdigit():
                stix_to_tid[oid] = rid.upper()
                break
    remap: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "revoked-by":
            continue
        src = obj.get("source_ref")
        tgt = obj.get("target_ref")
        old_tid = stix_to_tid.get(src)
        new_tid = stix_to_tid.get(tgt)
        if old_tid and new_tid and old_tid != new_tid:
            remap[old_tid] = new_tid
    print("STIX revoked-by remap entries:", len(remap))
    return remap


def load_attack_bundle(corpus_path: str | None) -> None:
    """Populate ATTACK_BUNDLE, ALLOWLIST, DEPRECATION_REMAP (module globals)."""
    global ATTACK_BUNDLE, ALLOWLIST, DEPRECATION_REMAP
    raw = load_attack_bundle_raw(corpus_path)
    ATTACK_BUNDLE = json.loads(raw)
    ALLOWLIST = allowlist_from_bundle(ATTACK_BUNDLE)
    DEPRECATION_REMAP = {**deprecation_remap_from_bundle(ATTACK_BUNDLE), **EXTRA_DEPRECATION_REMAP}
    print(f"Loaded {len(ALLOWLIST)} technique IDs in v{ATTACK_VERSION} allowlist.")


def root_id(tid: str) -> str:
    return tid.upper().split(".", 1)[0]


def chain_remap_tid(tid: str) -> str:
    u = tid.upper().strip()
    for _ in range(8):
        nxt = DEPRECATION_REMAP.get(u)
        if nxt is None:
            nxt = DEPRECATION_REMAP.get(root_id(u))
        if not nxt or nxt == u:
            break
        u = nxt
    return u


def is_allowed_id(tid: str, allow: set[str] | None = None) -> bool:
    allow = allow if allow is not None else ALLOWLIST
    u = tid.upper().strip()
    if u in allow:
        return True
    return root_id(u) in allow


def parent_fallback_if_needed(tid: str, allow: set[str]) -> str | None:
    """If sub-technique missing but root Txxxx is in allowlist, use root (documented policy)."""
    u = tid.upper().strip()
    if u in allow:
        return u
    r = root_id(u)
    if r in allow and r != u:
        return r
    return None


def normalize_summary_text(text: str) -> str:
    if not text:
        return ""
    t = text.replace("\r\n", "\n").strip()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"(?i)^(summary:|description:|abstract:)\s*", "", t)
    if len(t) > 2500:
        t = t[:2500] + "…"
    return t


def normalize_tag_list(tags: list[Any] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for t in tags or []:
        if not t:
            continue
        u = chain_remap_tid(str(t))
        if not u.startswith("T"):
            continue
        if not is_allowed_id(u):
            fb = parent_fallback_if_needed(u, ALLOWLIST)
            if fb:
                u = fb
            else:
                continue
        if u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= MAX_TECHNIQUES_PER_FINDING:
            break
    # Deterministic order (plan §4): sorted for stable completions
    out.sort(key=lambda x: (root_id(x), x))
    return out


def format_mitre_list(tags: list[str]) -> str:
    return "['" + "','".join(tags) + "']\n"


def compute_row_inverse_weights(dataset) -> list[float]:
    """Sqrt-inverse frequency weight per row (plan: weighted sampling)."""
    tc = Counter(t for row in dataset for t in row["tags_norm"])
    w = []
    for row in dataset:
        m = min(tc[t] for t in row["tags_norm"])
        w.append(1.0 / math.sqrt(max(m, 1)))
    return w


def weighted_resample_dataset(dataset, seed: int = 42):
    """Resample train rows with replacement using inverse-frequency weights (approx weighted sampler)."""
    import random

    weights = compute_row_inverse_weights(dataset)
    s = sum(weights)
    norm = [x * len(dataset) / s for x in weights]
    rng = random.Random(seed)
    idx = rng.choices(range(len(dataset)), weights=norm, k=len(dataset))
    return dataset.select(idx)


def cap_rows_per_tag(dataset, max_rows_per_tag: int, seed: int = 42):
    import random

    tag_counts = Counter(t for row in dataset for t in row["tags_norm"])
    drop: set[int] = set()
    for tag, cnt in tag_counts.most_common():
        if cnt <= max_rows_per_tag:
            break
        idxs = [i for i, row in enumerate(dataset) if tag in row["tags_norm"]]
        random.Random(seed).shuffle(idxs)
        for j in idxs[max_rows_per_tag:]:
            drop.add(j)
    if not drop:
        return dataset
    keep = [i for i in range(len(dataset)) if i not in drop]
    print(f"Head cap: dropped {len(drop)} rows (max {max_rows_per_tag} rows per tag)")
    return dataset.select(keep)


def dedupe_by_content(dataset, text_key: str = "text1_norm", tag_key: str = "tags_norm"):
    seen: set[tuple[str, tuple[str, ...]]] = set()
    keep_idx: list[int] = []
    for i, row in enumerate(dataset):
        key = (row[text_key], tuple(row[tag_key]))
        if key in seen:
            continue
        seen.add(key)
        keep_idx.append(i)
    return dataset.select(keep_idx)


def tag_cardinality_stats(dataset, tag_key: str = "tags_norm") -> dict[str, Any]:
    lens = [len(row[tag_key]) for row in dataset]
    c = Counter(lens)
    return {
        "mean_labels": sum(lens) / max(len(lens), 1),
        "max_labels": max(lens) if lens else 0,
        "cardinality_histogram": dict(sorted(c.items())),
    }


def raw_tag_invalid_rate_from_hf(dataset, mitre_key: str = "mitre_tags", limit: int | None = None):
    """Count raw tags not mappable to allowlist after remap + parent fallback."""
    bad, tot = 0, 0
    n = min(len(dataset), limit or len(dataset))
    for i in range(n):
        row = dataset[i]
        for t in row.get(mitre_key) or []:
            tot += 1
            u = chain_remap_tid(str(t))
            if not u.startswith("T") or not is_allowed_id(u):
                if parent_fallback_if_needed(u, ALLOWLIST) is None:
                    bad += 1
    return bad, tot, (bad / tot) if tot else 0.0


def oversample_tail(dataset, max_per_tag: int = 12, rare_threshold: int = 80, seed: int = 42):
    import random
    from datasets import concatenate_datasets

    tag_counts = Counter(t for row in dataset for t in row["tags_norm"])
    rare_tags = {t for t, c in tag_counts.items() if c < rare_threshold}
    extra_idx: list[int] = []
    for i, row in enumerate(dataset):
        if any(t in rare_tags for t in row["tags_norm"]):
            m = max(tag_counts[u] for u in row["tags_norm"])
            extra_idx.extend(
                [i] * min(max_per_tag, max(1, rare_threshold // max(m, 1)))
            )
    if not extra_idx:
        return dataset
    aug = dataset.select(extra_idx)
    return concatenate_datasets([dataset, aug]).shuffle(seed=seed)


def inverse_frequency_dupes(dataset, max_extra: int = 3, seed: int = 42):
    import random
    from datasets import concatenate_datasets

    tag_counts = Counter(t for row in dataset for t in row["tags_norm"])
    max_c = max(tag_counts.values()) if tag_counts else 1
    extras: list[int] = []
    for i, row in enumerate(dataset):
        min_c = min(tag_counts[t] for t in row["tags_norm"])
        ratio = max_c / max(min_c, 1)
        n_extra = min(max_extra, max(0, int(math.log2(ratio)) - 1))
        extras.extend([i] * n_extra)
    if not extras:
        return dataset
    random.Random(seed).shuffle(extras)
    return concatenate_datasets([dataset, dataset.select(extras)]).shuffle(seed=seed)
