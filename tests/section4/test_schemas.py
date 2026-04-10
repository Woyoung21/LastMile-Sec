"""Pydantic model validation for Section 4 schemas."""

from __future__ import annotations

import pytest

from src.section4_remediation.schemas import (
    RemediationOutput,
    RemediationStep,
    StepType,
    VerificationIssue,
    VerificationResult,
)


def _make_step(**overrides) -> dict:
    base = {
        "step_number": 1,
        "title": "Disable anonymous access",
        "command_or_action": "Set-GPO -Name 'AnonymousAccess' -Value Disabled",
        "explanation": "Prevents unauthenticated enumeration of SAM accounts.",
        "vendor_product": "Windows Server",
    }
    base.update(overrides)
    return base


def _make_output(**overrides) -> dict:
    base = {
        "steps": [_make_step()],
        "priority": "high",
        "estimated_effort": "15 minutes",
        "prerequisites": ["Domain Admin access"],
        "verification": "Run gpresult /r and confirm the setting is applied.",
        "source_control_ids": ["CIS-2.3.10.4"],
    }
    base.update(overrides)
    return base


def test_step_round_trip() -> None:
    s = RemediationStep(**_make_step())
    d = s.model_dump()
    assert d["step_number"] == 1
    assert d["title"] == "Disable anonymous access"
    assert d["vendor_product"] == "Windows Server"


def test_step_vendor_product_optional() -> None:
    s = RemediationStep(**_make_step(vendor_product=None))
    assert s.vendor_product is None


def test_output_round_trip() -> None:
    o = RemediationOutput(**_make_output())
    d = o.model_dump()
    assert len(d["steps"]) == 1
    assert d["priority"] == "high"
    assert d["source_control_ids"] == ["CIS-2.3.10.4"]


def test_output_defaults() -> None:
    o = RemediationOutput(
        steps=[RemediationStep(**_make_step())],
        priority="medium",
        estimated_effort="10 minutes",
        verification="check it",
    )
    assert o.prerequisites == []
    assert o.source_control_ids == []


def test_output_multiple_steps() -> None:
    steps = [_make_step(step_number=i, title=f"Step {i}") for i in range(1, 4)]
    o = RemediationOutput(**_make_output(steps=steps))
    assert len(o.steps) == 3
    assert o.steps[2].step_number == 3


def test_verification_issue_model() -> None:
    vi = VerificationIssue(
        check="grounding", severity="warning", message="No overlap"
    )
    assert vi.check == "grounding"
    assert vi.severity == "warning"


def test_verification_result_defaults() -> None:
    vr = VerificationResult()
    assert vr.grounding_score == 0.0
    assert vr.relevance_score == 0.0
    assert vr.completeness_score == 0.0
    assert vr.substep_quality_score == 0.0
    assert vr.passed is False
    assert vr.issues == []
    assert vr.attempts == 1


def test_verification_result_passing() -> None:
    vr = VerificationResult(
        grounding_score=0.9,
        relevance_score=0.8,
        completeness_score=1.0,
        substep_quality_score=0.85,
        passed=True,
        attempts=1,
    )
    assert vr.passed is True
    assert vr.grounding_score == 0.9
    assert vr.substep_quality_score == 0.85


def test_step_type_field() -> None:
    s = RemediationStep(**_make_step(step_type="hardening"))
    assert s.step_type == "hardening"


def test_step_type_optional() -> None:
    s = RemediationStep(**_make_step())
    assert s.step_type is None


def test_step_type_all_values() -> None:
    for st in ("investigation", "hardening", "monitoring"):
        s = RemediationStep(**_make_step(step_type=st))
        assert s.step_type == st


def test_step_type_in_dump() -> None:
    s = RemediationStep(**_make_step(step_type="monitoring"))
    d = s.model_dump()
    assert d["step_type"] == "monitoring"
