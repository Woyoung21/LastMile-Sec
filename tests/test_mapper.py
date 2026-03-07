import torch

import src.section2_report_map.mapper as mapper_module
from src.section2_report_map.mapper import (
    ActianVectorAIDBClient,
    FindingReport,
    Mapper,
    MitreValidator,
    ReferenceExample,
    VectorDBNotReadyError,
    VectorDBReadiness,
)
from src.section2_report_map.config import ATTACKMapperConfig


class FakeEmbedder:
    def __init__(self):
        self.calls = []

    def encode(self, text: str):
        self.calls.append(text)
        return [0.25, 0.5, 0.75]


class FakeVectorDB:
    def __init__(self, results, ready: bool = True, reason: str = "OK"):
        self.results = results
        self.calls = []
        self.ready = ready
        self.reason = reason

    def query_similar(self, embedding, top_k):
        self.calls.append((embedding, top_k))
        return self.results[:top_k]

    def check_collection_ready(self, collection_name, expected_dim, min_vectors):
        vector_count = max(min_vectors, 1) if self.ready else 0
        return VectorDBReadiness(
            connected=True,
            collection_exists=self.ready,
            opened=self.ready,
            vector_count=vector_count,
            probe_ok=self.ready,
            ready=self.ready,
            reason=self.reason,
            address="mock_addr",
            collection=collection_name,
        )


class FakeSearchResult:
    def __init__(self, technical_summary: str, mitre_ids, score: float):
        self.payload = {
            "technical_summary": technical_summary,
            "mitre_ids": mitre_ids,
        }
        self.score = score


class FakeCortexError(Exception):
    pass


class FakeCortexClient:
    def __init__(self, results=None, error: Exception | None = None):
        self.results = results or []
        self.error = error
        self.calls = []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.results


def test_mapper_local_mode_uses_reporter_input_and_rag_context():
    embedder = FakeEmbedder()
    vector_db = FakeVectorDB(
        [
            ReferenceExample(
                technical_summary="Historical web exploit activity matched public-facing application abuse.",
                mitre_ids=["T1190"],
                similarity_score=0.93,
            ),
            ReferenceExample(
                technical_summary="A prior credentialed shell event used valid accounts over SSH.",
                mitre_ids=["T1078", "T1021"],
                similarity_score=0.87,
            ),
        ]
    )

    captured_prompts = []

    def fake_local_generator(prompt: str):
        captured_prompts.append(prompt)
        return "T1190\nT9999"

    mapper = Mapper(
        routing_mode="local",
        embedder=embedder,
        vector_db_client=vector_db,
        validator=MitreValidator(known_ids={"T1190", "T1078", "T1021"}),
        local_generator=fake_local_generator,
    )

    result = mapper.map_finding(
        FindingReport(
            technical_summary="A vulnerable public-facing web service can allow remote code execution.",
            source_metadata={"hostname": "web-01", "log_source": "nessus"},
            severity_score=9.1,
        )
    )

    assert result.mitre_ids == ["T1190"]
    assert result.validation_passed is False
    assert result.metadata["source_agent"] == "Reporter"
    assert result.metadata["mapping_agent"] == "Mistral-7B-LoRA"
    assert result.metadata["db_context"] == "Actian-VectorAI"
    assert len(result.reference_examples) == 2
    assert embedder.calls == ["A vulnerable public-facing web service can allow remote code execution."]
    assert vector_db.calls[0][1] == 2
    assert "Reference Examples from Database" in captured_prompts[0]
    assert "A vulnerable public-facing web service can allow remote code execution." in captured_prompts[0]
    timing = result.metadata.get("timing_ms")
    assert isinstance(timing, dict)
    assert timing["total_ms"] >= 0.0


def test_actian_vector_ai_client_search_normalizes_cortex_results():
    cortex_client = FakeCortexClient(
        results=[
            FakeSearchResult(
                technical_summary="Historical web exploit activity matched public-facing application abuse.",
                mitre_ids=["T1190"],
                score=0.93,
            ),
            FakeSearchResult(
                technical_summary="A prior credentialed shell event used valid accounts over SSH.",
                mitre_ids=["T1078", "T1021"],
                score=0.87,
            ),
        ]
    )
    client = ActianVectorAIDBClient(client=cortex_client, cortex_error_cls=FakeCortexError)

    results = client.query_similar([0.25, 0.5, 0.75], top_k=2)

    assert [item.mitre_ids for item in results] == [["T1190"], ["T1078", "T1021"]]
    assert results[0].technical_summary.startswith("Historical web exploit activity")
    assert results[0].similarity_score == 0.93
    assert cortex_client.calls[0]["collection_name"] == "mitre_v18_1"
    assert cortex_client.calls[0]["query"] == [0.25, 0.5, 0.75]
    assert cortex_client.calls[0]["top_k"] == 2
    assert cortex_client.calls[0]["with_payload"] is True


def test_actian_vector_ai_client_returns_empty_on_cortex_error():
    cortex_client = FakeCortexClient(error=FakeCortexError("collection missing"))
    client = ActianVectorAIDBClient(client=cortex_client, cortex_error_cls=FakeCortexError)

    results = client.query_similar([0.25, 0.5, 0.75], top_k=2)

    assert results == []


def test_actian_vector_ai_client_retries_once_on_goaway(monkeypatch):
    class RetryOnceCortexClient:
        def __init__(self):
            self.calls = 0

        def search(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise FakeCortexError("GOAWAY received: too_many_pings")
            return [
                FakeSearchResult(
                    technical_summary="Recovered after transient GOAWAY",
                    mitre_ids=["T1190"],
                    score=0.99,
                )
            ]

    monkeypatch.setattr(mapper_module.time, "sleep", lambda _: None)
    cortex_client = RetryOnceCortexClient()
    client = ActianVectorAIDBClient(client=cortex_client, cortex_error_cls=FakeCortexError)

    results = client.query_similar([0.1, 0.2, 0.3], top_k=1)

    assert cortex_client.calls == 2
    assert len(results) == 1
    assert results[0].mitre_ids == ["T1190"]


def test_mapper_accepts_reporter_style_json_and_cloud_json_output():
    embedder = FakeEmbedder()
    vector_db = FakeVectorDB([])

    class FakeCloudResponse:
        def __init__(self, text: str):
            self.text = text

    class FakeCloudModels:
        def __init__(self):
            self.calls = 0

        def generate_content(self, **kwargs):
            self.calls += 1
            return FakeCloudResponse('{"techniques": [{"id": "T1078"}, {"id": "T0000"}]}')

    class FakeCloudClient:
        def __init__(self):
            self.models = FakeCloudModels()

    mapper = Mapper(
        routing_mode="cloud",
        cloud_client=FakeCloudClient(),
        embedder=embedder,
        vector_db_client=vector_db,
        validator=MitreValidator(known_ids={"T1078"}),
    )

    reporter_json = {
        "cvss_score": 7.5,
        "metadata": {
            "technical_summary": "The service accepts default credentials, allowing authenticated access.",
            "hostname": "switch-02",
            "log_source": "scanner",
        },
    }

    result = mapper.map_finding(reporter_json)

    assert result.mitre_ids == ["T1078"]
    assert result.validation_passed is False
    assert result.source_metadata == {"hostname": "switch-02", "log_source": "scanner"}
    assert result.severity_score == 7.5
    assert result.metadata["mapping_agent"] == "Gemini-2.5-Flash"


def test_vector_db_readiness_missing_collection_fails_strict(monkeypatch):
    monkeypatch.setattr(ATTACKMapperConfig, "REQUIRE_RAG", True)
    vector_db = FakeVectorDB([], ready=False, reason="COLLECTION_MISSING")

    try:
        Mapper(
            routing_mode="local",
            embedder=FakeEmbedder(),
            vector_db_client=vector_db,
            validator=MitreValidator(known_ids={"T1190"}),
            local_generator=lambda _: "T1190",
        )
        assert False, "Expected strict mode to fail on unready VectorDB"
    except VectorDBNotReadyError:
        pass


def test_vector_db_readiness_ok_passes_strict(monkeypatch):
    monkeypatch.setattr(ATTACKMapperConfig, "REQUIRE_RAG", True)
    mapper = Mapper(
        routing_mode="local",
        embedder=FakeEmbedder(),
        vector_db_client=FakeVectorDB([], ready=True),
        validator=MitreValidator(known_ids={"T1190"}),
        local_generator=lambda _: "T1190",
    )
    assert mapper.vector_db_status.ready is True
    assert mapper.vector_db_status.reason == "OK"


def test_mapper_stats_include_vector_db_status(monkeypatch):
    monkeypatch.setattr(ATTACKMapperConfig, "REQUIRE_RAG", True)
    monkeypatch.setattr(ATTACKMapperConfig, "ENABLE_TIMING", True)
    mapper = Mapper(
        routing_mode="local",
        embedder=FakeEmbedder(),
        vector_db_client=FakeVectorDB([], ready=True),
        validator=MitreValidator(known_ids={"T1190"}),
        local_generator=lambda _: "T1190",
    )
    packet = {
        "findings": [
            {
                "title": "Test Finding",
                "metadata": {
                    "technical_summary": "A suspicious port scan was observed.",
                },
            }
        ]
    }
    mapped_packet = mapper.process_packet(packet)
    status = mapped_packet["metadata"]["mapper_stats"]["vector_db_status"]
    assert status["ready"] is True
    timing = mapped_packet["metadata"]["mapper_stats"]["timing"]
    assert timing["count"] == 1.0
    assert timing["avg_total_ms"] >= 0.0
    local_runtime = mapped_packet["metadata"]["mapper_stats"]["local_runtime"]
    assert "require_cuda" in local_runtime


def test_local_generator_requires_cuda_when_enabled(monkeypatch):
    monkeypatch.setattr(ATTACKMapperConfig, "REQUIRE_RAG", False)
    monkeypatch.setattr(ATTACKMapperConfig, "REQUIRE_CUDA", True)
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)

    mapper = Mapper(
        routing_mode="local",
        embedder=FakeEmbedder(),
        vector_db_client=FakeVectorDB([], ready=True),
        validator=MitreValidator(known_ids={"T1190"}),
    )

    try:
        mapper._get_local_generator()
        assert False, "Expected strict CUDA mode to fail without CUDA"
    except RuntimeError as exc:
        assert "CUDA is required for local mapper mode" in str(exc)


def test_run_local_mapping_direct_generate_slices_prompt_and_passes_generation_args(monkeypatch):
    class FakeTokenizer:
        def __init__(self):
            self.pad_token_id = 0
            self.eos_token_id = 2
            self.last_decoded = None

        def __call__(self, prompt: str, return_tensors: str = "pt"):
            assert return_tensors == "pt"
            return {
                "input_ids": torch.tensor([[10, 11, 12]], dtype=torch.long),
                "attention_mask": torch.tensor([[1, 1, 1]], dtype=torch.long),
            }

        def decode(self, token_ids, skip_special_tokens: bool = True):
            self.last_decoded = token_ids.tolist()
            assert skip_special_tokens is True
            return "T1110"

    class FakeModel:
        def __init__(self):
            self.last_generate_kwargs = None

        def generate(self, **kwargs):
            self.last_generate_kwargs = kwargs
            tail = torch.tensor([[77, 88]], dtype=torch.long, device=kwargs["input_ids"].device)
            return torch.cat([kwargs["input_ids"], tail], dim=1)

    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)

    mapper = Mapper(
        routing_mode="local",
        embedder=FakeEmbedder(),
        vector_db_client=FakeVectorDB([], ready=True),
        validator=MitreValidator(known_ids={"T1110"}),
    )
    mapper.local_model = FakeModel()
    mapper.local_tokenizer = FakeTokenizer()
    mapper.local_generator = "direct_generate"

    report = FindingReport(
        technical_summary="Test summary",
        source_metadata={},
        severity_score=5.0,
    )
    output = mapper._run_local_mapping(report, [])

    assert output == "T1110"
    gen_kwargs = mapper.local_model.last_generate_kwargs
    assert gen_kwargs["max_new_tokens"] == ATTACKMapperConfig.LOCAL_MAX_NEW_TOKENS
    assert gen_kwargs["do_sample"] is False
    assert gen_kwargs["pad_token_id"] == mapper.local_tokenizer.pad_token_id
    assert gen_kwargs["eos_token_id"] == mapper.local_tokenizer.eos_token_id
    assert mapper.local_tokenizer.last_decoded == [77, 88]
