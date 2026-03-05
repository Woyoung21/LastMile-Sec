"""
Section 2 end-to-end integration test.

Feeds a realistic Section 1 JSON packet through Reporter -> Mapper
with mocked LLM / VectorAI clients so the test runs offline and fast.
"""

import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.section2_report_map.mapper import (
    FindingReport,
    Mapper,
    MitreValidator,
    ReferenceExample,
    VectorDBReadiness,
)
from src.section2_report_map.reporter import Reporter


# ---------------------------------------------------------------------------
# Fakes — no network calls, no GPU
# ---------------------------------------------------------------------------

class FakeGeminiResponse:
    def __init__(self, text: str):
        self.text = text


class FakeGeminiModels:
    """Simulates google.genai.Client().models for both Reporter and Mapper."""

    def generate_content(self, *, model, contents, config=None):
        if "summary" in (config or {}).get("system_instruction", "").lower():
            return FakeGeminiResponse(
                "OpenSSH 7.9 is vulnerable to CVE-2023-38408, enabling remote code "
                "execution through forwarded ssh-agent PKCS#11 library abuse over SSH."
            )
        return FakeGeminiResponse('{"techniques": [{"id": "T1190"}]}')


class FakeGeminiClient:
    def __init__(self):
        self.models = FakeGeminiModels()


class FakeEmbedder:
    def encode(self, text: str):
        return [0.1, 0.2, 0.3]


class FakeVectorDB:
    """Returns a canned historical example mimicking Actian VectorAI output."""

    def check_collection_ready(self, collection_name, expected_dim, min_vectors):
        return VectorDBReadiness(
            connected=True,
            collection_exists=True,
            opened=True,
            vector_count=max(min_vectors, 1),
            probe_ok=True,
            ready=True,
            reason="OK",
            address="mock_addr",
            collection=collection_name,
        )

    def query_similar(self, embedding, top_k=2):
        return [
            ReferenceExample(
                technical_summary="Historical SSH exploit matched public-facing application abuse.",
                mitre_ids=["T1190"],
                similarity_score=0.93,
            ),
        ]


def fake_local_generator(prompt: str) -> str:
    """Simulate Mistral-7B LoRA returning technique IDs."""
    return "T1190\nT1133"


# ---------------------------------------------------------------------------
# Realistic Section 1 packet (single finding)
# ---------------------------------------------------------------------------

SAMPLE_PACKET = {
    "id": "test-packet-001",
    "source_type": "vulnerability_report",
    "source_file": "integration_test_report.pdf",
    "source_hash": "abc123",
    "timestamp": "2026-02-13T12:00:00",
    "report_date": None,
    "findings": [
        {
            "id": "finding-001",
            "severity": "critical",
            "title": "OPENBSD OPENSSH < 9.3P2 RCE VULNERABILITY",
            "description": (
                "OpenBSD OpenSSH is prone to a remote code execution (RCE) "
                "vulnerability in OpenSSH's forwarded ssh-agent."
            ),
            "affected_assets": [{"identifier": "192.168.1.10", "asset_type": "host"}],
            "raw_excerpt": (
                "CRITICAL (CVSS: 9.8)\nNVT: OPENBSD OPENSSH < 9.3P2 RCE VULNERABILITY\n"
                "830/TCP\nOpenBSD OpenSSH is prone to a remote code execution (RCE) "
                "vulnerability in OpenSSH's forwarded ssh-agent.\nRelated CVE: CVE-2023-38408"
            ),
            "cve_ids": ["CVE-2023-38408"],
            "cvss_score": 9.8,
            "recommendations": [],
            "references": [],
            "source_ip": None,
            "destination_ip": None,
            "protocol": None,
            "timestamp_observed": None,
            "metadata": {
                "nvt_oid": "1.3.6.1.4.1.25623.1.0.104869",
                "ports": ["830"],
                "services": ["SSH"],
                "hostnames": [],
                "extracted_by_parser_version": "1.0.0",
            },
        },
        {
            "id": "finding-002",
            "severity": "high",
            "title": "Multiple Failed System Logons",
            "description": (
                "Source IP 192.168.1.105 attempted 50+ logins to 'Administrator' "
                "account within 2 minutes. Final attempt was successful."
            ),
            "affected_assets": [{"identifier": "192.168.1.200", "asset_type": "host"}],
            "raw_excerpt": "",
            "cve_ids": [],
            "cvss_score": None,
            "recommendations": [],
            "references": [],
            "source_ip": "192.168.1.105",
            "destination_ip": "192.168.1.200",
            "protocol": "SMB",
            "timestamp_observed": "2026-02-13T10:30:00",
            "metadata": {
                "ports": ["445"],
                "services": ["Windows Event Log (Security)"],
                "hostnames": [],
            },
        },
    ],
    "finding_count": 2,
    "critical_count": 1,
    "high_count": 1,
    "metadata": {
        "parser_name": "pdf_parser",
        "parser_version": "1.0.0",
        "processed_at": "2026-02-13T12:00:00",
        "processing_time_ms": 100,
        "warnings": [],
        "errors": [],
    },
    "document_summary": "Integration test packet for Section 2 pipeline validation.",
}


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def run_integration_test():
    print("LastMile-Sec: Section 2 Integration Test (offline)")
    print("-" * 60)

    # --- Step 1: Reporter ---
    print("\nStep 1: Reporter Agent (fake Gemini client)")
    reporter = Reporter(client=FakeGeminiClient(), enable_cache=False)
    packet = reporter.process_packet(SAMPLE_PACKET)

    for finding in packet["findings"]:
        meta = finding.get("metadata", {})
        summary = meta.get("technical_summary", "")
        assert summary, f"Finding {finding['id']} has no technical_summary"
        print(f"  [{finding['id']}] summary: {summary[:90]}...")

    print("  Reporter: OK")

    # --- Step 2: Mapper (local mode with fakes) ---
    print("\nStep 2: Mapper Agent (fake Mistral LoRA + fake Actian VectorAI)")
    mapper = Mapper(
        routing_mode="local",
        embedder=FakeEmbedder(),
        vector_db_client=FakeVectorDB(),
        validator=MitreValidator(),
        local_generator=fake_local_generator,
    )
    packet = mapper.process_packet(packet)

    for finding in packet["findings"]:
        meta = finding.get("metadata", {})
        mapping = meta.get("mitre_mapping", {})
        mitre_ids = mapping.get("mitre_ids", [])
        print(f"  [{finding['id']}] MITRE IDs: {mitre_ids}")
        assert isinstance(mitre_ids, list), "mitre_ids should be a list"
        assert mapping.get("routing_mode") == "local"
        assert mapping.get("mapping_agent") == "Mistral-7B-LoRA"
        assert mapping.get("db_context") == "Actian-VectorAI"

    # --- Validate overall structure ---
    mapper_stats = packet.get("metadata", {}).get("mapper_stats", {})
    assert mapper_stats.get("total_findings_mapped", 0) > 0, "No findings were mapped"
    assert mapper_stats.get("routing_mode") == "local"

    reporter_stats = packet.get("metadata", {}).get("reporter_stats", {})
    assert reporter_stats.get("total_findings_summarized", 0) > 0

    print(f"\n  Mapper stats: {mapper_stats}")
    print(f"  Reporter stats: {reporter_stats}")

    print("\n" + "-" * 60)
    print("Integration test PASSED — full Reporter -> Mapper pipeline works.")


if __name__ == "__main__":
    run_integration_test()
