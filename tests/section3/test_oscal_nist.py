"""OSCAL parser, MITRE mapping load, SecurityControl guardrails (no Neo4j)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.section3_rag_correlation.ingestion.oscal_nist import (
    VENDOR_NIST_800_53,
    load_attack_mapping,
    nist_prefixed_control_id,
    normalize_nist_control_id,
    oscal_control_to_security_control,
    sanitize_oscal_prose,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ac-1", "AC-01"),
        ("AC-01", "AC-01"),
        ("AC-1", "AC-01"),
        ("ac-2", "AC-02"),
        ("ac-12", "AC-12"),
        ("cm-3", "CM-03"),
        ("ac-2.1", "AC-02.1"),
    ],
)
def test_normalize_nist_control_id_padded_join_key(raw: str, expected: str) -> None:
    assert normalize_nist_control_id(raw) == expected


def test_nist_prefixed_control_id() -> None:
    assert nist_prefixed_control_id("AC-01") == "NIST-AC-01"


def test_sanitize_oscal_prose_strips_insert_params() -> None:
    s = "Develop policy {{ insert: param, ac-01_odp.01 }} for staff."
    out = sanitize_oscal_prose(s)
    assert "{{" not in out
    assert "}}" not in out
    assert "[ASSIGNMENT]" in out


def test_oscal_control_to_security_control_vendor_and_id(tmp_path: Path) -> None:
    raw = {
        "id": "ac-2",
        "title": "Account Management",
        "parts": [
            {
                "prose": "Do the thing {{ insert: param, x }}.",
            }
        ],
    }
    mitre = {"AC-02": ["T1078", "T1556.009"]}
    sc = oscal_control_to_security_control(raw, mitre)
    assert sc is not None
    assert sc.control_id == "NIST-AC-02"
    assert sc.vendor_product == VENDOR_NIST_800_53
    assert sc.mitre_mapping == ["T1078", "T1556.009"]
    assert "{{" not in sc.remediation_steps


def test_oscal_control_empty_parts_returns_none() -> None:
    raw = {"id": "ac-1", "title": "", "parts": []}
    assert oscal_control_to_security_control(raw, {}) is None


def test_load_attack_mapping_mitigates_only(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    path.write_text(
        json.dumps(
            {
                "mapping_objects": [
                    {
                        "capability_id": "AC-02",
                        "attack_object_id": "T1556.009",
                        "mapping_type": "mitigates",
                    },
                    {
                        "capability_id": "AC-02",
                        "attack_object_id": "T1078",
                        "mapping_type": "mitigates",
                    },
                    {
                        "capability_id": None,
                        "attack_object_id": "T1496",
                        "mapping_type": "non_mappable",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    d = load_attack_mapping(path)
    assert d == {"AC-02": ["T1078", "T1556.009"]}


def test_mitre_join_ac02_variants(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    path.write_text(
        json.dumps(
            {
                "mapping_objects": [
                    {
                        "capability_id": "AC-02",
                        "attack_object_id": "T1078",
                        "mapping_type": "mitigates",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    mitre = load_attack_mapping(path)
    raw = {"id": "ac-2", "title": "X", "parts": [{"prose": "text."}]}
    sc = oscal_control_to_security_control(raw, mitre)
    assert sc is not None
    assert sc.mitre_mapping == ["T1078"]
