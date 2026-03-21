"""merge_security_control: embedding validation and Cypher calls (mocked driver)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.section3_rag_correlation import config
from src.section3_rag_correlation.graph.merge_controls import merge_security_control
from src.section3_rag_correlation.schemas import SecurityControl


def _emb() -> list[float]:
    return [0.0] * config.EMBEDDING_DIMENSIONS


def test_rejects_wrong_embedding_dimension() -> None:
    driver = MagicMock()
    ctrl = SecurityControl(
        control_id="CIS-1.1.1",
        vendor_product="Windows Server",
        remediation_steps="Do the thing",
        mitre_mapping=["T1190"],
    )
    with pytest.raises(ValueError, match="768"):
        merge_security_control(driver, ctrl, [0.0] * 10)


def test_two_session_runs_when_mitre_ids_present() -> None:
    session = MagicMock()
    driver = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    driver.session.return_value.__exit__.return_value = None

    ctrl = SecurityControl(
        control_id="NIST-AC-2",
        vendor_product="Meraki MS",
        remediation_steps="Harden",
        mitre_mapping=["T1021.001", "T1190"],
        audit_procedure="Check registry",
    )
    merge_security_control(driver, ctrl, _emb())

    assert session.run.call_count == 2
    c0 = session.run.call_args_list[0]
    c1 = session.run.call_args_list[1]
    assert "MERGE (v:Vendor" in c0.args[0]
    assert "MITIGATES" in c1.args[0]
    assert c0.kwargs["control_id"] == "NIST-AC-2"
    assert len(c0.kwargs["embedding"]) == config.EMBEDDING_DIMENSIONS
    assert c1.kwargs["control_id"] == "NIST-AC-2"
    assert c1.kwargs["mitre_ids"] == ["T1021.001", "T1190"]


def test_single_session_run_when_no_mitre_ids() -> None:
    session = MagicMock()
    driver = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    driver.session.return_value.__exit__.return_value = None

    ctrl = SecurityControl(
        control_id="ORPHAN",
        vendor_product="Generic",
        remediation_steps="Step",
        mitre_mapping=None,
    )
    merge_security_control(driver, ctrl, _emb())
    assert session.run.call_count == 1
    assert "MERGE (v:Vendor" in session.run.call_args_list[0].args[0]
