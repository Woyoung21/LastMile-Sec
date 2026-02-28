from src.section2_report_map.reporter import Reporter


class FakeResponse:
    def __init__(self, text: str):
        self.text = text


class SequenceModels:
    def __init__(self, response_text: str = "", error: Exception | None = None):
        self.response_text = response_text
        self.error = error
        self.calls = 0

    def generate_content(self, **kwargs):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return FakeResponse(self.response_text)


class FakeClient:
    def __init__(self, response_text: str = "", error: Exception | None = None):
        self.models = SequenceModels(response_text=response_text, error=error)


def _finding_fixture() -> dict:
    return {
        "title": "OpenBSD OpenSSH < 9.3p2 RCE Vulnerability (CVSS: 9.8)",
        "description": "OpenSSH forwarded ssh-agent support can be abused for code execution.",
        "raw_excerpt": "Vulnerability Insight: PKCS#11 libraries can be abused via a forwarded agent socket.",
        "cve_ids": ["CVE-2023-38408"],
        "metadata": {
            "services": ["ssh"],
            "ports": ["22/tcp"],
        },
    }


def test_reporter_uses_cached_summary_without_calling_model(tmp_path):
    finding = _finding_fixture()
    warm_client = FakeClient(
        "OpenSSH forwarded ssh-agent handling can allow remote code execution through PKCS#11 library abuse."
    )
    warm_reporter = Reporter(
        client=warm_client,
        cache_dir=tmp_path,
        enable_cache=True,
        sleep_seconds_between_requests=0,
    )

    first_summary, first_cache_hit = warm_reporter.generate_summary(finding)

    cold_client = FakeClient(error=RuntimeError("model should not be called"))
    cached_reporter = Reporter(
        client=cold_client,
        cache_dir=tmp_path,
        enable_cache=True,
        sleep_seconds_between_requests=0,
    )

    second_summary, second_cache_hit = cached_reporter.generate_summary(finding)

    assert first_cache_hit is False
    assert second_cache_hit is True
    assert second_summary == first_summary
    assert cold_client.models.calls == 0


def test_reporter_does_not_cache_fallback_summaries(tmp_path):
    finding = _finding_fixture()
    failing_client = FakeClient(error=RuntimeError("network down"))
    reporter = Reporter(
        client=failing_client,
        cache_dir=tmp_path,
        enable_cache=True,
        sleep_seconds_between_requests=0,
    )

    first_summary, first_cache_hit = reporter.generate_summary(finding)
    second_summary, second_cache_hit = reporter.generate_summary(finding)

    assert first_cache_hit is False
    assert second_cache_hit is False
    assert first_summary == second_summary
    assert reporter.cache_hits == 0
    assert reporter.cache_misses == 2
