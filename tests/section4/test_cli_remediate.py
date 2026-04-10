"""CLI integration tests for Section 4 remediate (mocked generator)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.section4_remediation.cli.remediate import (
    _iter_correlated_json,
    _iter_findings_with_correlation,
    _write_remediated,
    run_remediate,
)
from src.section4_remediation.schemas import (
    RemediationOutput,
    RemediationProvenance,
    RemediationStep,
    VerificationResult,
)


def _sample_correlated_data() -> dict:
    return {
        "id": "pkt-001",
        "source_type": "pcap",
        "findings": [
            {
                "id": "f-001",
                "severity": "high",
                "metadata": {
                    "technical_summary": "RDP connection on port 3389",
                    "mitre_mapping": {"mitre_ids": ["T1110"]},
                    "rag_correlation": {
                        "best_control": {
                            "control_id": "CIS-2.3.10.4",
                            "vendor_product": "Windows Server",
                            "remediation_steps": "Disable anonymous access",
                            "audit_procedure": "gpresult /r",
                        },
                        "vendor_controls": [],
                        "framework_controls": [],
                    },
                },
            },
            {
                "id": "f-002",
                "severity": "low",
                "metadata": {
                    "technical_summary": "DNS query to external resolver",
                },
            },
        ],
    }


def test_iter_findings_with_correlation() -> None:
    data = _sample_correlated_data()
    pairs = _iter_findings_with_correlation(data)
    assert len(pairs) == 1
    finding, corr = pairs[0]
    assert finding["id"] == "f-001"
    assert corr["best_control"]["control_id"] == "CIS-2.3.10.4"


def test_iter_findings_skips_no_correlation() -> None:
    data = {"findings": [{"id": "x", "metadata": {"technical_summary": "test"}}]}
    assert _iter_findings_with_correlation(data) == []


def test_iter_correlated_json(tmp_path: Path) -> None:
    (tmp_path / "a_correlated.json").write_text("{}")
    (tmp_path / "b_correlated.json").write_text("{}")
    (tmp_path / "other.json").write_text("{}")
    result = _iter_correlated_json(tmp_path)
    assert len(result) == 2
    assert all("_correlated.json" in p.name for p in result)


def test_iter_correlated_json_empty_dir(tmp_path: Path) -> None:
    assert _iter_correlated_json(tmp_path) == []


def test_iter_correlated_json_nonexistent() -> None:
    assert _iter_correlated_json(Path("/nonexistent/dir")) == []


def test_write_remediated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.section4_remediation.cli.remediate.config.REMEDIATED_JSON_DIR",
        tmp_path,
    )
    data = {"findings": []}
    out = _write_remediated(Path("test_correlated.json"), data)
    assert out.name.startswith("test_remediated_")
    assert out.name.endswith(".json")
    assert out.exists()
    loaded = json.loads(out.read_text())
    assert loaded == data


def test_write_remediated_strips_correlated_suffix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.section4_remediation.cli.remediate.config.REMEDIATED_JSON_DIR",
        tmp_path,
    )
    out = _write_remediated(Path("report_mapped_correlated.json"), {"x": 1})
    assert out.name.startswith("report_mapped_remediated_")
    assert out.name.endswith(".json")


@patch("src.section4_remediation.cli.remediate.generate_with_verification")
def test_run_remediate_end_to_end(
    mock_gwv: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "src.section4_remediation.cli.remediate.config.REMEDIATED_JSON_DIR",
        tmp_path / "out",
    )

    mock_output = RemediationOutput(
        steps=[RemediationStep(
            step_number=1,
            title="Fix",
            command_or_action="do it",
            explanation="because",
        )],
        priority="high",
        estimated_effort="10 min",
        verification="check",
        source_control_ids=["CIS-2.3.10.4"],
    )
    mock_vr = VerificationResult(
        grounding_score=0.9,
        relevance_score=0.8,
        completeness_score=1.0,
        passed=True,
        attempts=1,
    )
    mock_gwv.return_value = (
        mock_output,
        mock_vr,
        RemediationProvenance(mode="graph_only"),
    )

    input_file = tmp_path / "test_correlated.json"
    input_file.write_text(json.dumps(_sample_correlated_data()))

    run_remediate(json_path=input_file, skip_llm_judge=True)

    out_dir = tmp_path / "out"
    remediated = list(out_dir.glob("*_remediated_*.json"))
    assert len(remediated) == 1
    data = json.loads(remediated[0].read_text())
    finding = data["findings"][0]
    assert "remediation" in finding["metadata"]
    rem = finding["metadata"]["remediation"]
    assert rem["priority"] == "high"
    assert rem["selfrag_verification"]["passed"] is True
    assert len(rem["steps"]) == 1
