"""Tests for Section 2 MappingValidator (T1102 semantic gate + T1190 fallback)."""

import pytest

from src.section2_report_map.config import ATTACKMapperConfig
from src.section2_report_map.validation import MappingValidator, summary_supports_t1190_fallback


@pytest.fixture
def validator():
    return MappingValidator()


def test_t1190_fallback_when_only_t1102_rejected_jquery_style(validator):
    summary = (
        "The host 172.31.2.42 exposes jQuery version 1.10.2 via HTTP and HTTPS on ports 80 and 443, "
        "which is end-of-life and no longer receives security updates."
    )
    r = validator.validate(
        candidate_ids=["T1102"],
        raw_model_output="['T1102']",
        technical_summary=summary,
    )
    assert r.accepted_ids == ["T1190"]
    assert any(i.gate == "fallback" and i.severity == "info" for i in r.issues)
    assert r.passed


def test_t1190_fallback_when_only_t1102_subtechnique(validator):
    summary = "Nginx 1.20 is end-of-life on public-facing ports 80 and 443."
    r = validator.validate(
        candidate_ids=["T1102.002"],
        raw_model_output="['T1102.002']",
        technical_summary=summary,
    )
    assert r.accepted_ids == ["T1190"]


def test_no_fallback_when_summary_lacks_initial_access_keywords(validator):
    r = validator.validate(
        candidate_ids=["T1102"],
        raw_model_output="['T1102']",
        technical_summary="The scheduled job completed successfully.",
    )
    assert r.accepted_ids == []


def test_no_fallback_when_config_disabled(monkeypatch, validator):
    monkeypatch.setattr(ATTACKMapperConfig, "T1102_FALLBACK_T1190", False)
    summary = "EOL jQuery on HTTPS port 443, vulnerable to known flaws."
    r = validator.validate(
        candidate_ids=["T1102"],
        raw_model_output="['T1102']",
        technical_summary=summary,
    )
    assert r.accepted_ids == []


def test_no_fallback_when_t1102_not_in_rejected_path(validator):
    """Empty candidates should not get T1190 injected."""
    r = validator.validate(
        candidate_ids=[],
        raw_model_output="",
        technical_summary="end-of-life nginx on port 443",
    )
    assert r.accepted_ids == []


def test_keeps_t1190_when_model_emits_both_t1102_and_t1190(validator):
    # Avoid the substring "c2" so T1102 is semantically rejected (no C2 evidence).
    summary = "EOL nginx on public-facing HTTP; scanner reports exposure only."
    r = validator.validate(
        candidate_ids=["T1102", "T1190"],
        raw_model_output="['T1102', 'T1190']",
        technical_summary=summary,
    )
    assert r.accepted_ids == ["T1190"]
    assert not any(i.gate == "fallback" for i in r.issues)


def test_summary_supports_t1190_fallback_helper():
    assert summary_supports_t1190_fallback("Software is end-of-life and vulnerable on a public-facing port.")
    assert not summary_supports_t1190_fallback("Nothing relevant here.")
