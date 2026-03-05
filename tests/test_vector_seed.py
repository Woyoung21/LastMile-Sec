import json

from scripts.seed_vector_db import dedupe_seed_records, parse_attack_corpus, parse_mapped_findings


def test_parse_attack_corpus_extracts_valid_attack_patterns(tmp_path):
    corpus = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Valid Technique",
                "description": "Technique description.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1190"},
                ],
            },
            {
                "type": "attack-pattern",
                "name": "Revoked Technique",
                "description": "Should be skipped",
                "revoked": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059"},
                ],
            },
            {
                "type": "attack-pattern",
                "name": "Deprecated Technique",
                "description": "Should be skipped",
                "x_mitre_deprecated": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1110"},
                ],
            },
        ],
    }
    corpus_path = tmp_path / "enterprise-attack-18.1.json"
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")

    records = parse_attack_corpus(corpus_path)

    assert len(records) == 1
    assert records[0]["mitre_ids"] == ["T1190"]
    assert records[0]["source"] == "attack_corpus"


def test_parse_attack_corpus_includes_sub_technique_ids(tmp_path):
    corpus = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "name": "OS Credential Dumping: LSASS Memory",
                "description": "Dumping LSASS process memory.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1003.001"},
                ],
            },
        ],
    }
    corpus_path = tmp_path / "enterprise-attack-18.1.json"
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")

    records = parse_attack_corpus(corpus_path)

    assert len(records) == 1
    assert records[0]["mitre_ids"] == ["T1003.001"]
    assert records[0]["technical_summary"] == "Dumping LSASS process memory."


def test_parse_mapped_findings_only_keeps_valid_summaries_and_ids(tmp_path):
    mapped_packet = {
        "source_file": "sample.json",
        "findings": [
            {
                "title": "Valid",
                "metadata": {
                    "technical_summary": "Valid summary.",
                    "mitre_mapping": {"mitre_ids": ["T1078"]},
                },
            },
            {
                "title": "Missing Summary",
                "metadata": {
                    "mitre_mapping": {"mitre_ids": ["T1190"]},
                },
            },
            {
                "title": "Empty IDs",
                "metadata": {
                    "technical_summary": "No ids",
                    "mitre_mapping": {"mitre_ids": []},
                },
            },
        ],
    }
    mapped_path = tmp_path / "mapped.json"
    mapped_path.write_text(json.dumps(mapped_packet), encoding="utf-8")

    records = parse_mapped_findings(tmp_path)

    assert len(records) == 1
    assert records[0]["mitre_ids"] == ["T1078"]
    assert records[0]["source"] == "local_mapped"


def test_dedupe_seed_records_merges_duplicate_summary_and_mitre_ids():
    rows = [
        {
            "technical_summary": "  Same summary text  ",
            "mitre_ids": ["T1190", "T1078"],
        },
        {
            "technical_summary": "Same summary text",
            "mitre_ids": ["t1078", "t1190"],
        },
        {
            "technical_summary": "Different summary",
            "mitre_ids": ["T1110"],
        },
    ]

    deduped = dedupe_seed_records(rows)

    assert len(deduped) == 2
    first_ids = sorted(deduped[0]["mitre_ids"])
    second_ids = sorted(deduped[1]["mitre_ids"])
    assert ["T1078", "T1190"] in (first_ids, second_ids)


def test_dedupe_prefers_local_mapped_for_identical_content():
    rows = [
        {
            "technical_summary": "Same summary",
            "mitre_ids": ["T1190"],
            "source": "attack_corpus",
        },
        {
            "technical_summary": "Same summary",
            "mitre_ids": ["T1190"],
            "source": "local_mapped",
        },
    ]

    deduped = dedupe_seed_records(rows)

    assert len(deduped) == 1
    assert deduped[0]["source"] == "local_mapped"
