"""Self-RAG verifier tests with synthetic data (no API key needed)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.section4_remediation.schemas import (
    RemediationOutput,
    RemediationProvenance,
    RemediationStep,
    VerificationResult,
)
from src.section4_remediation.selfrag import (
    SelfRAGVerifier,
    _check_completeness,
    _check_relevance,
    _check_substep_quality,
    _heuristic_grounding,
    _is_cli_step,
    _token_set,
    generate_with_verification,
)


# -- Helpers --

def _step(
    num: int = 1,
    title: str = "Disable anonymous access",
    action: str = "GP: set EveryoneIncludesAnonymous to Disabled",
    explanation: str = "Prevents unauthenticated enumeration",
) -> RemediationStep:
    return RemediationStep(
        step_number=num,
        title=title,
        command_or_action=action,
        explanation=explanation,
        vendor_product="Windows Server",
    )


_SENTINEL = object()


def _output(steps=_SENTINEL, control_ids=_SENTINEL) -> RemediationOutput:
    return RemediationOutput(
        steps=[_step()] if steps is _SENTINEL else steps,
        priority="high",
        estimated_effort="15 minutes",
        prerequisites=["Admin access"],
        verification="Run gpresult /r",
        source_control_ids=["CIS-2.3.10.4"] if control_ids is _SENTINEL else control_ids,
    )


def _correlation() -> dict:
    return {
        "best_control": {
            "control_id": "CIS-2.3.10.4",
            "vendor_product": "Windows Server",
            "remediation_steps": (
                "To establish the recommended configuration via GP, set the "
                "following UI path to Disabled: Computer Configuration\\Policies\\"
                "Windows Settings\\Security Settings\\Local Policies\\Security Options\\"
                "Network access: Let Everyone permissions apply to anonymous users"
            ),
            "audit_procedure": (
                "Navigate to the UI Path articulated in the Remediation section and "
                "confirm it is set as prescribed. Registry: "
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa:EveryoneIncludesAnonymous"
            ),
        },
        "vendor_controls": [
            {
                "control": {
                    "control_id": "CIS-2.3.10.3",
                    "vendor_product": "Windows Server",
                    "remediation_steps": "Enable RestrictAnonymous via GP.",
                    "audit_procedure": "Check registry RestrictAnonymous.",
                },
            },
        ],
        "framework_controls": [],
    }


# -- Token set --

def test_token_set_lowercases_and_filters() -> None:
    tokens = _token_set("The Quick Brown Fox 42")
    assert "the" not in tokens
    assert "quick" in tokens
    assert "brown" in tokens
    assert "fox" in tokens


def test_token_set_empty() -> None:
    assert _token_set("") == set()


# -- Heuristic grounding --

def test_heuristic_grounding_full_overlap() -> None:
    source = (
        "Disable EveryoneIncludesAnonymous via GP Computer Configuration "
        "Policies Windows anonymous enumeration unauthenticated"
    )
    output = _output()
    score, issues = _heuristic_grounding(output, source)
    assert score == 1.0
    assert len(issues) == 0


def test_heuristic_grounding_no_overlap() -> None:
    source = "completely unrelated text about network routing protocols"
    step = _step(
        title="Install patch KB12345",
        action="wusa.exe /install /quiet KB12345",
        explanation="Fixes CVE-2024-0001",
    )
    output = _output(steps=[step])
    score, issues = _heuristic_grounding(output, source)
    assert score == 0.0
    assert any(i.check == "grounding" for i in issues)


def test_heuristic_grounding_empty_steps() -> None:
    output = _output(steps=[])
    score, issues = _heuristic_grounding(output, "some source")
    assert score == 0.0
    assert any("No steps" in i.message for i in issues)


# -- Relevance --

def test_relevance_good_overlap() -> None:
    output = _output(steps=[
        _step(
            title="Block RDP brute force T1110",
            action="Lockout policy for RDP port 3389",
            explanation="Mitigates T1110 brute force on RDP connection",
        ),
    ])
    summary = "RDP brute force connection from 10.0.0.1 on port 3389"
    score, issues = _check_relevance(output, summary, ["T1110"])
    assert score > 0.3


def test_relevance_no_mitre_ref() -> None:
    output = _output(steps=[
        _step(
            title="Generic hardening",
            action="Apply patches",
            explanation="General security improvement",
        ),
    ])
    summary = "RDP brute force"
    score, issues = _check_relevance(output, summary, ["T1110", "T1563.002"])
    mitre_issues = [i for i in issues if "MITRE" in i.message]
    assert len(mitre_issues) > 0


def test_relevance_empty_steps() -> None:
    output = _output(steps=[])
    score, issues = _check_relevance(output, "summary", ["T1110"])
    assert score == 0.0


# -- Completeness --

def test_completeness_all_referenced() -> None:
    output = _output(control_ids=["CIS-2.3.10.4", "CIS-2.3.10.3"])
    score, issues = _check_completeness(output, _correlation())
    assert score == 1.0
    assert len(issues) == 0


def test_completeness_partial() -> None:
    output = _output(control_ids=["CIS-2.3.10.4"])
    score, issues = _check_completeness(output, _correlation())
    assert 0.0 < score < 1.0
    assert any(i.check == "completeness" for i in issues)


def test_completeness_none_referenced() -> None:
    output = _output(control_ids=["UNKNOWN-1"])
    score, issues = _check_completeness(output, _correlation())
    assert score == 0.0


def test_completeness_graph_plus_search_limitations_bumps_score(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.section4_remediation.selfrag.config.COMPLETENESS_THRESHOLD", 0.5)
    output = _output(control_ids=["UNKNOWN-1"])
    output.limitations.append("Official vendor docs used; graph controls were generic.")
    score, _issues = _check_completeness(
        output, _correlation(), graph_plus_search=True,
    )
    assert score >= 0.5


def test_completeness_empty_correlation() -> None:
    output = _output(control_ids=[])
    score, issues = _check_completeness(output, {})
    assert score == 1.0


def test_completeness_prefix_match_short_to_long() -> None:
    """Gemini outputs short IDs; graph has full CIS-style IDs."""
    long_id_correlation = {
        "best_control": {
            "control_id": "2.3.10.4 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled' (Automated)",
            "vendor_product": "Windows Server",
            "remediation_steps": "Set via GP.",
        },
        "vendor_controls": [
            {
                "control": {
                    "control_id": "2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only) (Automated)",
                    "vendor_product": "Windows Server",
                    "remediation_steps": "Enable RestrictAnonymous.",
                },
            },
        ],
        "framework_controls": [],
    }
    output = _output(control_ids=["2.3.10.4", "2.3.10.3"])
    score, issues = _check_completeness(output, long_id_correlation)
    assert score == 1.0
    assert len(issues) == 0


def test_completeness_prefix_match_partial() -> None:
    """Only one of two long IDs matched by a short prefix."""
    long_id_correlation = {
        "best_control": {
            "control_id": "2.3.10.4 (L1) Ensure something",
            "vendor_product": "Windows",
            "remediation_steps": "fix",
        },
        "vendor_controls": [
            {
                "control": {
                    "control_id": "9.1.2 (L1) Some other control",
                    "vendor_product": "Windows",
                    "remediation_steps": "fix",
                },
            },
        ],
        "framework_controls": [],
    }
    output = _output(control_ids=["2.3.10.4"])
    score, issues = _check_completeness(output, long_id_correlation)
    assert score == 0.5
    assert any(i.check == "completeness" for i in issues)


# -- SelfRAGVerifier --

def test_verifier_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.section4_remediation.selfrag.config.GROUNDING_THRESHOLD", 0.5)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.RELEVANCE_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.COMPLETENESS_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.SUBSTEP_QUALITY_THRESHOLD", 0.0)

    verifier = SelfRAGVerifier(use_llm_judge=False)
    output = _output(control_ids=["CIS-2.3.10.4", "CIS-2.3.10.3"])
    result = verifier.verify(
        output, _correlation(),
        "anonymous access enumeration EveryoneIncludesAnonymous",
        ["T1110"],
    )
    assert result.grounding_score > 0
    assert isinstance(result, VerificationResult)


def test_verifier_fail_grounding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.section4_remediation.selfrag.config.GROUNDING_THRESHOLD", 0.99)
    verifier = SelfRAGVerifier(use_llm_judge=False)
    step = _step(
        title="Unrelated action",
        action="apt-get install nginx",
        explanation="Install a web server",
    )
    output = _output(steps=[step])
    result = verifier.verify(
        output, _correlation(),
        "anonymous access",
        ["T1110"],
    )
    assert result.passed is False


# -- generate_with_verification --

@patch("src.section4_remediation.selfrag.generate_remediation")
def test_generate_with_verification_passes_first_try(mock_gen: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.section4_remediation.selfrag.config.GROUNDING_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.RELEVANCE_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.COMPLETENESS_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.SUBSTEP_QUALITY_THRESHOLD", 0.0)

    mock_gen.return_value = (_output(), RemediationProvenance(mode="graph_only"))

    finding = {
        "severity": "high",
        "metadata": {
            "technical_summary": "RDP brute force",
            "mitre_mapping": {"mitre_ids": ["T1110"]},
        },
    }
    output, vr, prov = generate_with_verification(
        finding, _correlation(), use_llm_judge=False, max_retries=0,
    )
    assert isinstance(output, RemediationOutput)
    assert prov.mode == "graph_only"
    assert vr.attempts == 1
    mock_gen.assert_called_once()


@patch("src.section4_remediation.selfrag.generate_remediation")
def test_generate_with_verification_retries(mock_gen: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.section4_remediation.selfrag.config.GROUNDING_THRESHOLD", 0.99)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.RELEVANCE_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.COMPLETENESS_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.SUBSTEP_QUALITY_THRESHOLD", 0.0)

    bad_step = _step(title="Unrelated", action="do something random xyz123", explanation="irrelevant abc789")
    mock_gen.return_value = (_output(steps=[bad_step]), RemediationProvenance(mode="graph_only"))

    finding = {
        "severity": "high",
        "metadata": {
            "technical_summary": "anonymous access",
            "mitre_mapping": {"mitre_ids": ["T1110"]},
        },
    }
    output, vr, _prov = generate_with_verification(
        finding, _correlation(), use_llm_judge=False, max_retries=2,
    )
    assert vr.attempts == 3
    assert mock_gen.call_count == 3
    assert vr.passed is False


# -- CLI step detection --

def test_is_cli_step_powershell() -> None:
    assert _is_cli_step("Set-GPO -Name 'Foo' -Value Disabled") is True


def test_is_cli_step_linux() -> None:
    assert _is_cli_step("sudo iptables -A INPUT -p tcp --dport 3389 -j DROP") is True


def test_is_cli_step_ui_path() -> None:
    assert _is_cli_step("Computer Configuration\\Policies\\Windows Settings") is False


def test_is_cli_step_description() -> None:
    assert _is_cli_step("Navigate to the Security Options page") is False


# -- Substep quality --

def _step_with_substeps(
    num: int = 1,
    substeps: list[str] | None = None,
    breadcrumb: str | None = None,
    action: str = "Computer Configuration\\Policies\\Windows Settings",
    step_type: str | None = "hardening",
) -> RemediationStep:
    return RemediationStep(
        step_number=num,
        title=f"Step {num}",
        command_or_action=action,
        explanation="Hardens the system.",
        vendor_product="Windows Server",
        step_type=step_type,
        ui_breadcrumb=breadcrumb,
        substeps=substeps or [],
    )


def test_substep_quality_all_good() -> None:
    step = _step_with_substeps(
        substeps=[
            "Open Group Policy Editor.",
            "Navigate to Security Options.",
            "Set the policy to Disabled.",
            "Verify you should see the setting is now Disabled.",
        ],
        breadcrumb="Computer Configuration > Policies > Security Options",
    )
    output = _output(steps=[step])
    score, issues = _check_substep_quality(output)
    assert score == 1.0
    errors = [i for i in issues if i.severity == "error"]
    assert len(errors) == 0


def test_substep_quality_empty_substeps() -> None:
    step = _step_with_substeps(substeps=[])
    output = _output(steps=[step])
    score, issues = _check_substep_quality(output)
    assert score == 0.0
    errors = [i for i in issues if i.severity == "error"]
    assert any("0 substeps" in e.message for e in errors)


def test_substep_quality_too_few_substeps() -> None:
    step = _step_with_substeps(substeps=["Open editor.", "Change setting."])
    output = _output(steps=[step])
    score, issues = _check_substep_quality(output)
    assert score == 1.0  # 2 substeps -> warning, not error -> step still passes
    warnings = [i for i in issues if i.severity == "warning" and "substep(s)" in i.message]
    assert len(warnings) == 1


def test_substep_quality_missing_breadcrumb_on_ui_step() -> None:
    step = _step_with_substeps(
        substeps=["Open GPO.", "Navigate.", "Set Disabled."],
        breadcrumb=None,
        action="Computer Configuration\\Policies\\Security Options",
    )
    output = _output(steps=[step])
    score, issues = _check_substep_quality(output)
    breadcrumb_issues = [i for i in issues if "ui_breadcrumb" in i.message]
    assert len(breadcrumb_issues) == 1


def test_substep_quality_cli_step_no_breadcrumb_ok() -> None:
    step = _step_with_substeps(
        substeps=["Run the command.", "Check output.", "Confirm success."],
        breadcrumb=None,
        action="Set-GPO -Name 'Test' -Value Disabled",
    )
    output = _output(steps=[step])
    score, issues = _check_substep_quality(output)
    breadcrumb_issues = [i for i in issues if "ui_breadcrumb" in i.message]
    assert len(breadcrumb_issues) == 0


def test_substep_quality_no_confirmation_hint() -> None:
    step = _step_with_substeps(
        substeps=["Open editor.", "Navigate to path.", "Change the setting."],
        breadcrumb="GPO > Security Options",
    )
    output = _output(steps=[step])
    score, issues = _check_substep_quality(output)
    confirm_issues = [i for i in issues if "confirmation" in i.message]
    assert len(confirm_issues) == 1


def test_substep_quality_confirmation_detected() -> None:
    step = _step_with_substeps(
        substeps=[
            "Open editor.",
            "Navigate to path.",
            "Change the setting.",
            "You should see the policy is now set to Disabled.",
        ],
        breadcrumb="GPO > Security Options",
    )
    output = _output(steps=[step])
    score, issues = _check_substep_quality(output)
    confirm_issues = [i for i in issues if "confirmation" in i.message]
    assert len(confirm_issues) == 0


def test_substep_quality_empty_steps() -> None:
    output = _output(steps=[])
    score, issues = _check_substep_quality(output)
    assert score == 0.0
    assert any("No steps" in i.message for i in issues)


def test_substep_quality_mixed_pass_fail() -> None:
    good = _step_with_substeps(
        num=1,
        substeps=["Open GPO.", "Navigate.", "Confirm the setting shows Disabled."],
        breadcrumb="GPO > Security",
    )
    bad = _step_with_substeps(num=2, substeps=[])
    output = _output(steps=[good, bad])
    score, issues = _check_substep_quality(output)
    assert score == 0.5


def test_verifier_includes_substep_quality(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.section4_remediation.selfrag.config.GROUNDING_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.RELEVANCE_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.COMPLETENESS_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.SUBSTEP_QUALITY_THRESHOLD", 0.0)

    verifier = SelfRAGVerifier(use_llm_judge=False)
    output = _output()
    result = verifier.verify(
        output, _correlation(),
        "anonymous access",
        ["T1110"],
    )
    assert hasattr(result, "substep_quality_score")
    assert isinstance(result.substep_quality_score, float)


def test_verifier_fails_on_substep_quality(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.section4_remediation.selfrag.config.GROUNDING_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.RELEVANCE_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.COMPLETENESS_THRESHOLD", 0.0)
    monkeypatch.setattr("src.section4_remediation.selfrag.config.SUBSTEP_QUALITY_THRESHOLD", 0.99)

    step = _step_with_substeps(substeps=[])
    verifier = SelfRAGVerifier(use_llm_judge=False)
    output = _output(steps=[step])
    result = verifier.verify(
        output, _correlation(),
        "anonymous access",
        ["T1110"],
    )
    assert result.passed is False
    assert result.substep_quality_score < 0.99
