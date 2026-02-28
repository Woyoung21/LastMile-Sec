import copy

from src.section2_report_map.config import ReporterConfig
from src.section2_report_map.reporter import Reporter


class FakeResponse:
    def __init__(self, text: str):
        self.text = text


class FakeModels:
    def __init__(self, text: str):
        self.text = text
        self.calls = 0

    def generate_content(self, **kwargs):
        self.calls += 1
        return FakeResponse(self.text)


class FakeClient:
    def __init__(self, text: str):
        self.models = FakeModels(text)


def _packet_fixture() -> dict:
    return {
        "source_file": "sample.json",
        "findings": [
            {
                "title": "OpenBSD OpenSSH < 9.3p2 RCE Vulnerability (CVSS: 9.8)",
                "description": "OpenSSH forwarded ssh-agent support can be abused for code execution.",
                "raw_excerpt": "Vulnerability Insight: PKCS#11 libraries can be abused via a forwarded agent socket.",
                "cve_ids": ["CVE-2023-38408"],
                "metadata": {
                    "services": ["ssh"],
                    "ports": ["22/tcp"],
                },
            }
        ],
    }


def test_reporter_sample_processes_packet_with_mocked_client(tmp_path):
    packet = copy.deepcopy(_packet_fixture())
    client = FakeClient(
        "OpenSSH forwarded ssh-agent handling can allow remote code execution through PKCS#11 library abuse."
    )
    reporter = Reporter(
        client=client,
        cache_dir=tmp_path,
        enable_cache=False,
        sleep_seconds_between_requests=0,
    )

    enriched = reporter.process_packet(packet)

    finding = enriched["findings"][0]
    metadata = finding["metadata"]
    stats = enriched["metadata"]["reporter_stats"]

    assert metadata["technical_summary"].endswith(".")
    assert "CVSS" not in metadata["technical_summary"]
    assert metadata["summary_source"] == "llm"
    assert metadata["summary_prompt_version"] == ReporterConfig.SUMMARY_PROMPT_VERSION
    assert metadata["summary_model"] == ReporterConfig.GEMINI_MODEL
    assert stats["total_findings_summarized"] == 1
    assert client.models.calls == 1
