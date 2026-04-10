"""Decide whether to use Google Search grounding for a remedation request."""

from __future__ import annotations

from typing import Any

from src.section4_remediation import config


def _thin_vendor_hinted(
    tech_stack: list[str],
    technical_summary: str,
    finding: dict[str, Any] | None,
) -> bool:
    blob = technical_summary.lower()
    if finding:
        blob += " " + str(finding.get("title", "") or "").lower()
        blob += " " + str(finding.get("description", "") or "").lower()
    for key in config.THIN_CORPUS_VENDOR_SUBSTRINGS:
        if key and key in blob:
            return True
    for entry in tech_stack:
        el = entry.lower()
        for key in config.THIN_CORPUS_VENDOR_SUBSTRINGS:
            if key and key in el:
                return True
    return False


def should_augment_with_search(
    finding: dict[str, Any],
    correlation: dict[str, Any],
    tech_stack: list[str],
    *,
    cli_enable_search: bool,
) -> tuple[bool, str | None]:
    """Return (use_google_search_grounding, reason_if_true).

    When ``cli_enable_search`` is False, search is never used.
    """
    if not cli_enable_search:
        return False, None

    meta = finding.get("metadata") or {}
    summary = str(meta.get("technical_summary") or "")

    vendor_matched = bool(correlation.get("vendor_matched"))
    similarity = correlation.get("similarity_score")
    composite = correlation.get("composite_score")

    thin = _thin_vendor_hinted(tech_stack, summary, finding)

    if not vendor_matched and thin:
        return True, "vendor_unmatched_and_thin_corpus_vendor_hint"

    if not vendor_matched:
        low_sim = (
            isinstance(similarity, (int, float))
            and float(similarity) < config.SEARCH_TRIGGER_SIMILARITY_MAX
        )
        low_comp = (
            isinstance(composite, (int, float))
            and float(composite) < config.SEARCH_TRIGGER_COMPOSITE_MAX
        )
        if low_sim:
            return True, f"vendor_unmatched_low_similarity_{similarity}"
        if low_comp:
            return True, f"vendor_unmatched_low_composite_{composite}"

    return False, None
