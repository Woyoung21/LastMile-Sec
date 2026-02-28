import copy

from src.section2_report_map.reporter import Reporter


class FakeResponse:
    def __init__(self, text: str):
        self.text = text


class FakeModels:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def generate_content(self, **kwargs):
        self.calls += 1
        return FakeResponse(self._responses.pop(0))


class FakeClient:
    def __init__(self, responses):
        self.models = FakeModels(responses)


def _packet_fixture() -> dict:
    return {
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
            },
            {
                "title": "Default SNMP community string exposed",
                "description": "The device accepts the default public community string.",
                "raw_excerpt": "The SNMP agent responds to the default public community string.",
                "cve_ids": [],
                "metadata": {
                    "services": ["snmp"],
                    "ports": ["161/udp"],
                },
            },
        ]
    }


def test_reporter_uses_fallback_when_model_output_is_invalid(tmp_path):
    packet = copy.deepcopy(_packet_fixture())
    client = FakeClient(["[HIGH] OpenSSH issue with CVSS 9.8."])
    reporter = Reporter(
        client=client,
        cache_dir=tmp_path,
        enable_cache=False,
        sleep_seconds_between_requests=0,
    )

    enriched = reporter.process_packet(packet, max_findings=1)
    metadata = enriched["findings"][0]["metadata"]

    assert metadata["summary_source"] == "fallback"
    assert metadata["technical_summary"] == (
        "OpenBSD OpenSSH < 9.3p2 RCE Vulnerability affects the ssh service and is associated with CVE-2023-38408."
    )
    assert "CVSS" not in metadata["technical_summary"]


def test_reporter_process_packet_respects_max_findings(tmp_path):
    packet = copy.deepcopy(_packet_fixture())
    client = FakeClient(
        [
            "OpenSSH forwarded ssh-agent handling can allow remote code execution through PKCS#11 library abuse."
        ]
    )
    reporter = Reporter(
        client=client,
        cache_dir=tmp_path,
        enable_cache=False,
        sleep_seconds_between_requests=0,
    )

    enriched = reporter.process_packet(packet, max_findings=1)

    assert enriched["metadata"]["reporter_stats"]["total_findings_summarized"] == 1
    assert "technical_summary" in enriched["findings"][0]["metadata"]
    assert "technical_summary" not in enriched["findings"][1]["metadata"]
