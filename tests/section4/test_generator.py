"""Generator tests with mocked LLM (no API key needed)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.section4_remediation.generator import (
    _format_controls_text,
    build_remediation_metadata,
    generate_remediation,
)
from src.section4_remediation.schemas import (
    RemediationOutput,
    RemediationStep,
    VerificationResult,
)


# -- Helpers --

def _sample_finding() -> dict:
    return {
        "id": "f-001",
        "severity": "high",
        "metadata": {
            "technical_summary": "RDP connection from 10.0.0.1 to 192.168.1.1 on port 3389.",
            "mitre_mapping": {"mitre_ids": ["T1110", "T1563.002"]},
        },
    }


def _sample_correlation() -> dict:
    return {
        "best_control": {
            "control_id": "CIS-2.3.10.4",
            "vendor_product": "Windows Server",
            "remediation_steps": "Disable anonymous access via GP.",
            "audit_procedure": "Run gpresult /r.",
        },
        "vendor_controls": [
            {
                "control": {
                    "control_id": "CIS-2.3.10.3",
                    "vendor_product": "Windows Server",
                    "remediation_steps": "Enable RestrictAnonymous.",
                    "audit_procedure": "Check registry.",
                },
            },
        ],
        "framework_controls": [],
    }


def _mock_output() -> RemediationOutput:
    return RemediationOutput(
        steps=[
            RemediationStep(
                step_number=1,
                title="Disable anonymous access",
                command_or_action="GP: set Disabled",
                explanation="Prevents enumeration.",
                vendor_product="Windows Server",
            ),
        ],
        priority="high",
        estimated_effort="15 minutes",
        prerequisites=["Domain Admin"],
        verification="gpresult /r",
        source_control_ids=["CIS-2.3.10.4"],
    )


# -- Tests --

def test_format_controls_text_best_control() -> None:
    text, ids = _format_controls_text(_sample_correlation())
    assert "CIS-2.3.10.4" in text
    assert "[BEST MATCH]" in text
    assert "CIS-2.3.10.4" in ids
    assert "CIS-2.3.10.3" in ids


def test_format_controls_text_empty() -> None:
    text, ids = _format_controls_text({})
    assert "no source controls" in text.lower()
    assert ids == []


def test_format_controls_dedup() -> None:
    corr = _sample_correlation()
    corr["vendor_controls"].append({
        "control": {
            "control_id": "CIS-2.3.10.4",
            "vendor_product": "Windows Server",
            "remediation_steps": "dup",
        },
    })
    _, ids = _format_controls_text(corr)
    assert ids.count("CIS-2.3.10.4") == 1


@patch("src.section4_remediation.generator._get_llm")
def test_generate_remediation_calls_llm(mock_get_llm: MagicMock) -> None:
    expected = _mock_output()

    mock_llm = MagicMock()
    mock_structured = MagicMock()
    mock_llm.with_structured_output.return_value = mock_structured
    mock_get_llm.return_value = mock_llm

    with patch("src.section4_remediation.generator.REMEDIATION_PROMPT") as mock_prompt:
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = expected
        mock_prompt.__or__ = MagicMock(return_value=mock_chain)
        result = generate_remediation(
            _sample_finding(), _sample_correlation(), ["Windows Server"],
        )

    assert isinstance(result, RemediationOutput)
    assert len(result.steps) == 1
    assert result.priority == "high"
    mock_llm.with_structured_output.assert_called_once_with(RemediationOutput)
    mock_chain.invoke.assert_called_once()
    invoke_args = mock_chain.invoke.call_args[0][0]
    assert "technical_summary" in invoke_args
    assert invoke_args["severity"] == "high"


@patch("src.section4_remediation.generator._get_llm")
def test_generate_remediation_retry_uses_retry_prompt(mock_get_llm: MagicMock) -> None:
    expected = _mock_output()

    mock_llm = MagicMock()
    mock_structured = MagicMock()
    mock_llm.with_structured_output.return_value = mock_structured
    mock_get_llm.return_value = mock_llm

    with patch("src.section4_remediation.generator.RETRY_PROMPT") as mock_prompt:
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = expected
        mock_prompt.__or__ = MagicMock(return_value=mock_chain)
        result = generate_remediation(
            _sample_finding(),
            _sample_correlation(),
            rejection_issues="- Step 1 not grounded.",
        )

    assert isinstance(result, RemediationOutput)
    invoke_args = mock_chain.invoke.call_args[0][0]
    assert "rejection_issues" in invoke_args
    assert "Step 1 not grounded" in invoke_args["rejection_issues"]


def test_build_remediation_metadata_structure() -> None:
    output = _mock_output()
    vr = VerificationResult(
        grounding_score=0.85,
        relevance_score=0.7,
        completeness_score=1.0,
        passed=True,
        attempts=1,
    )
    meta = build_remediation_metadata(output, vr)
    assert "steps" in meta
    assert meta["priority"] == "high"
    assert meta["source_control_ids"] == ["CIS-2.3.10.4"]
    assert meta["selfrag_verification"]["passed"] is True
    assert meta["selfrag_verification"]["grounding_score"] == 0.85
    assert "generated_at" in meta
    assert "model" in meta
