"""Retrieval policy for when to enable Google Search grounding."""

from __future__ import annotations

import pytest

from src.section4_remediation import config
from src.section4_remediation.retrieval_policy import should_augment_with_search


def _finding(summary: str = "Meraki firewall allows SSH") -> dict:
    return {
        "title": "open port",
        "metadata": {"technical_summary": summary},
    }


def _correlation(
    *,
    vendor_matched: bool,
    similarity: float | None = 0.9,
    composite: float | None = 0.9,
) -> dict:
    return {
        "vendor_matched": vendor_matched,
        "similarity_score": similarity,
        "composite_score": composite,
    }


def test_search_disabled_when_cli_off() -> None:
    use, reason = should_augment_with_search(
        _finding(),
        _correlation(vendor_matched=False, similarity=0.1),
        ["Meraki MS", "NIST SP 800-53"],
        cli_enable_search=False,
    )
    assert use is False
    assert reason is None


def test_search_when_vendor_unmatched_and_thin_vendor_in_summary() -> None:
    use, reason = should_augment_with_search(
        _finding("Meraki MS allows SNMP v2c"),
        _correlation(vendor_matched=False),
        ["Windows Server", "NIST SP 800-53"],
        cli_enable_search=True,
    )
    assert use is True
    assert reason == "vendor_unmatched_and_thin_corpus_vendor_hint"


def test_search_when_vendor_unmatched_low_similarity() -> None:
    use, reason = should_augment_with_search(
        _finding("Generic weakness in network appliance"),
        _correlation(vendor_matched=False, similarity=0.1, composite=0.9),
        ["NIST SP 800-53"],
        cli_enable_search=True,
    )
    assert use is True
    assert "low_similarity" in (reason or "")


def test_no_search_when_vendor_matched(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "SEARCH_TRIGGER_SIMILARITY_MAX", 0.99)
    use, reason = should_augment_with_search(
        _finding("Meraki issue"),
        _correlation(vendor_matched=True, similarity=0.1),
        ["Meraki MS"],
        cli_enable_search=True,
    )
    assert use is False
    assert reason is None
