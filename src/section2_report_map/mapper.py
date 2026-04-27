"""
Hybrid, RAG-enhanced MITRE ATT&CK mapper for Section 2.

This mapper consumes Reporter output, retrieves similar historical examples
from Actian VectorAI, and routes mapping through either Gemini or a local
Mistral-7B LoRA adapter.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional

import google.genai
from pydantic import BaseModel, Field

from src.common.gemini_transient import invoke_with_transient_retry, parse_gemini_fallback_models

from .config import ATTACKMapperConfig, ReporterConfig
from .prompts import AttackMapperPrompts
from .validation import (
    MappingValidator,
    ValidationResult,
    _TACTIC_KEYWORD_MAP,
    _TECHNIQUE_TACTIC_ROOTS,
    summary_supports_t1102_web_service_c2,
)


class _LocalDecodingGuards:
    """Stopping criteria and logits processor for local LoRA inference.

    Provides two complementary mechanisms:
    - **StoppingCriteria**: halts generation as soon as a ``]`` token is emitted.
    - **LogitsProcessor**: after the opening ``[`` is seen, suppresses tokens
      that cannot appear in a valid Python list of ATT&CK IDs (e.g.
      ``['T1059', 'T1110']``).  This prevents mid-list hallucination while
      still allowing the model full freedom before the list begins.

    Both are built lazily so ``transformers`` is only imported when local
    inference is actually used.
    """

    _classes = None

    @classmethod
    def _ensure_imports(cls):
        if cls._classes is None:
            from transformers import (
                LogitsProcessor,
                LogitsProcessorList,
                StoppingCriteria,
                StoppingCriteriaList,
            )
            cls._classes = {
                "LogitsProcessor": LogitsProcessor,
                "LogitsProcessorList": LogitsProcessorList,
                "StoppingCriteria": StoppingCriteria,
                "StoppingCriteriaList": StoppingCriteriaList,
            }

    @classmethod
    def create_stopping_criteria(cls, tokenizer):
        """Return a ``StoppingCriteriaList`` that stops on ``]``."""
        cls._ensure_imports()
        SC = cls._classes["StoppingCriteria"]
        SCL = cls._classes["StoppingCriteriaList"]

        class _BracketStop(SC):
            def __init__(self, tok):
                super().__init__()
                self._tokenizer = tok

            def __call__(self, input_ids, scores, **kwargs):
                decoded = self._tokenizer.decode(
                    input_ids[0, -1], skip_special_tokens=True
                )
                return "]" in decoded

        return SCL([_BracketStop(tokenizer)])

    @classmethod
    def create_logits_processor(cls, tokenizer):
        """Return a ``LogitsProcessorList`` constraining output to valid ID lists.

        Allowed token vocabulary after ``[`` is detected:
        ``'``, ``T``, digits 0-9, ``.``, ``,``, `` `` (space), ``]``, ``\\n``.
        """
        cls._ensure_imports()
        import torch as _torch
        LP = cls._classes["LogitsProcessor"]
        LPL = cls._classes["LogitsProcessorList"]

        allowed_chars = set("'T0123456789., ]\n")
        allowed_token_ids: set[int] = set()
        for token_id in range(tokenizer.vocab_size):
            token_str = tokenizer.decode([token_id], skip_special_tokens=True)
            if token_str and all(ch in allowed_chars for ch in token_str):
                allowed_token_ids.add(token_id)
        if tokenizer.eos_token_id is not None:
            allowed_token_ids.add(tokenizer.eos_token_id)

        class _IDListConstraint(LP):
            def __init__(self, tok, allowed_ids: set[int]):
                super().__init__()
                self._tokenizer = tok
                self._allowed = allowed_ids
                self._active = False

            def __call__(self, input_ids, scores):
                if not self._active:
                    decoded_tail = self._tokenizer.decode(
                        input_ids[0, -3:], skip_special_tokens=True
                    )
                    if "[" in decoded_tail:
                        self._active = True

                if self._active:
                    mask = _torch.full_like(scores, float("-inf"))
                    for tid in self._allowed:
                        if tid < scores.shape[-1]:
                            mask[:, tid] = scores[:, tid]
                    return mask
                return scores

        return LPL([_IDListConstraint(tokenizer, allowed_token_ids)])


class VectorDBNotReadyError(RuntimeError):
    """Raised when strict RAG mode is enabled and VectorDB is not usable."""


class VectorDBReadiness(BaseModel):
    """Structured readiness status for VectorDB collection checks."""

    connected: bool = False
    collection_exists: bool = False
    opened: bool = False
    vector_count: int = 0
    probe_ok: bool = False
    ready: bool = False
    reason: str = "UNKNOWN"
    address: str = ""
    collection: str = ""


class FindingReport(BaseModel):
    """Normalized input expected from the upstream Reporter Agent.

    The Reporter enriches each finding with a ``technical_summary`` stored
    inside ``finding["metadata"]["technical_summary"]``.  The extra fields
    below let the Mapper carry forward context that the LoRA / cloud model
    can use for higher-confidence mapping.
    """

    technical_summary: str = Field(..., min_length=1)
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    severity_score: float | None = Field(default=None, ge=0.0, le=10.0)

    title: str = Field(default="", description="Finding title from the ingested report")
    cve_ids: list[str] = Field(default_factory=list, description="CVE identifiers associated with the finding")
    services: list[str] = Field(default_factory=list, description="Affected services (e.g. SSH, HTTP)")
    ports: list[str] = Field(default_factory=list, description="Affected ports")


class ReferenceExample(BaseModel):
    """A historical example retrieved from the vector database."""

    technical_summary: str
    mitre_ids: list[str] = Field(default_factory=list)
    similarity_score: float | None = None


class MitreMappingResult(BaseModel):
    """Validated mapper output."""

    finding_summary: str
    mitre_ids: list[str] = Field(default_factory=list)
    validation_passed: bool
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    severity_score: float | None = None
    reference_examples: list[ReferenceExample] = Field(default_factory=list)
    raw_model_output: str = ""
    routing_mode: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class MitreValidator:
    """Validate ATT&CK IDs against an Enterprise 18.1 registry."""

    _TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

    def __init__(
        self,
        framework_version: str = ATTACKMapperConfig.ATTACK_VERSION,
        known_ids: set[str] | None = None,
    ):
        self.framework_version = framework_version
        self.known_ids = {item.upper() for item in (known_ids or ATTACKMapperConfig.DEFAULT_ENTERPRISE_18_1_TECHNIQUE_IDS)}

    def validate_id(self, technique_id: str) -> bool:
        """Validate a single technique ID."""
        normalized = (technique_id or "").strip().upper()
        if not self._TECHNIQUE_PATTERN.match(normalized):
            return False

        root_id = normalized.split(".", 1)[0]
        return normalized in self.known_ids or root_id in self.known_ids

    def validate_many(self, technique_ids: list[str]) -> list[str]:
        """Validate, normalize, and de-duplicate technique IDs."""
        valid_ids: list[str] = []
        seen: set[str] = set()

        for technique_id in technique_ids:
            normalized = (technique_id or "").strip().upper()
            if normalized in seen:
                continue
            if self.validate_id(normalized):
                seen.add(normalized)
                valid_ids.append(normalized)

        return valid_ids


def _rerank_reference_examples(
    technical_summary: str,
    examples: list[ReferenceExample],
) -> list[ReferenceExample]:
    """Rerank vector hits: boost examples whose labeled tactics match summary keywords; downrank T1102 without C2 evidence."""
    if len(examples) <= 1:
        return examples

    summary_tactics: set[str] = set()
    sl = technical_summary.lower()
    for tactic, keywords in _TACTIC_KEYWORD_MAP.items():
        if any(kw in sl for kw in keywords):
            summary_tactics.add(tactic)

    c2_ok = summary_supports_t1102_web_service_c2(technical_summary)
    scored: list[tuple[float, ReferenceExample]] = []

    for ex in examples:
        base = float(ex.similarity_score if ex.similarity_score is not None else 0.0)
        bonus = 0.0
        for mid in ex.mitre_ids:
            root = mid.split(".", 1)[0].upper()
            tactics = _TECHNIQUE_TACTIC_ROOTS.get(root)
            if tactics and summary_tactics.intersection(set(tactics)):
                bonus += 0.12
            if root == "T1102" and not c2_ok:
                bonus -= 0.35
        scored.append((base + bonus, ex))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [ex for _, ex in scored]


class ActianVectorAIDBClient:
    """Actian VectorAI client wrapper backed by the cortex library."""

    def __init__(self, client=None, cortex_error_cls=None, address: str | None = None):
        self._distance_metric = None
        self._cortex_error_cls = cortex_error_cls
        self.address = address or ATTACKMapperConfig.VECTOR_DB_ADDRESS

        if client is not None:
            self.client = client
            if self._cortex_error_cls is None:
                self._cortex_error_cls = Exception
            return

        from cortex import CortexClient, CortexError, DistanceMetric

        # Initialize the client
        self.client = CortexClient(address=self.address)
        
        try:
            self.client.connect()
        except Exception as e:
            print(f"Warning: Could not connect to Actian VectorAI at {self.address}: {e}")
            # Non-fatal — Mapper can still run in zero-shot mode without RAG

        self._distance_metric = getattr(DistanceMetric, "COSINE", None)
        self._cortex_error_cls = CortexError

    def query_similar(self, embedding: list[float], top_k: int = ATTACKMapperConfig.VECTOR_DB_TOP_K) -> list[ReferenceExample]:
        """Return the top-k similar historical examples."""
        if self.client is None:
            return []

        search_kwargs = {
            "collection_name": ATTACKMapperConfig.VECTOR_DB_COLLECTION,
            "query": embedding,
            "top_k": top_k,
            "with_payload": True,
        }

        rows = None
        for attempt in range(2):
            try:
                rows = self.client.search(**search_kwargs)
                break
            except self._cortex_error_cls as exc:
                if attempt == 0 and self._is_goaway_or_ping_error(exc):
                    time.sleep(1)
                    continue
                return []
            except Exception as exc:
                if attempt == 0 and self._is_goaway_or_ping_error(exc):
                    time.sleep(1)
                    continue
                return []

        if rows is None:
            return []

        return [self._normalize_row(row) for row in rows[:top_k]]

    @staticmethod
    def _is_goaway_or_ping_error(exc: Exception) -> bool:
        """Return True for transient gRPC GOAWAY/keepalive throttling errors."""
        message = str(exc).upper()
        return "GOAWAY" in message or "TOO_MANY_PINGS" in message

    def _safe_get_vector_count(self, collection_name: str) -> int:
        """Best-effort vector count lookup."""
        if self.client is None:
            return 0
        try:
            count = self.client.get_vector_count(collection_name)
            return int(count or 0)
        except self._cortex_error_cls:
            return 0
        except Exception:
            return 0

    def _probe_search(self, collection_name: str, expected_dim: int) -> bool:
        """Execute a minimal probe query against the collection."""
        if self.client is None:
            return False
        try:
            self.client.search(
                collection_name=collection_name,
                query=[0.0] * expected_dim,
                top_k=1,
                with_payload=False,
            )
            return True
        except self._cortex_error_cls:
            return False
        except Exception:
            return False

    def check_collection_ready(
        self,
        collection_name: str,
        expected_dim: int,
        min_vectors: int,
    ) -> VectorDBReadiness:
        """Check if a collection can be used reliably for retrieval."""
        status = VectorDBReadiness(
            connected=False,
            collection_exists=False,
            opened=False,
            vector_count=0,
            probe_ok=False,
            ready=False,
            reason="CONNECT_FAILED",
            address=self.address,
            collection=collection_name,
        )

        if self.client is None:
            return status

        try:
            self.client.connect()
            status.connected = True
        except Exception:
            return status

        try:
            status.collection_exists = bool(self.client.has_collection(collection_name))
        except self._cortex_error_cls:
            status.reason = "COLLECTION_MISSING"
            return status
        except Exception:
            status.reason = "COLLECTION_MISSING"
            return status

        if not status.collection_exists:
            status.reason = "COLLECTION_MISSING"
            return status

        try:
            self.client.open_collection(collection_name)
            status.opened = True
        except self._cortex_error_cls:
            status.reason = "OPEN_FAILED"
            return status
        except Exception:
            status.reason = "OPEN_FAILED"
            return status

        status.vector_count = self._safe_get_vector_count(collection_name)
        if status.vector_count < min_vectors:
            status.reason = "COLLECTION_EMPTY"
            return status

        status.probe_ok = self._probe_search(collection_name, expected_dim)
        if not status.probe_ok:
            status.reason = "PROBE_FAILED"
            return status

        status.reason = "OK"
        status.ready = True
        return status

    def _normalize_row(self, row: Any) -> ReferenceExample:
        """Normalize a DB row into a ReferenceExample model."""
        if isinstance(row, ReferenceExample):
            return row

        if hasattr(row, "payload") and hasattr(row, "score"):
            payload = row.payload or {}
            raw_ids = payload.get("mitre_ids") or []
            if isinstance(raw_ids, str):
                raw_ids = [raw_ids]

            return ReferenceExample(
                technical_summary=payload.get("technical_summary", ""),
                mitre_ids=list(raw_ids),
                similarity_score=row.score,
            )

        if not isinstance(row, dict):
            raise TypeError("VectorAI rows must be SearchResult-like, dict-like, or ReferenceExample instances")

        raw_ids = row.get("mitre_ids") or row.get("verified_mitre_ids") or row.get("mitre_id") or []
        if isinstance(raw_ids, str):
            raw_ids = [raw_ids]

        return ReferenceExample(
            technical_summary=row.get("technical_summary") or row.get("summary") or row.get("text") or "",
            mitre_ids=list(raw_ids),
            similarity_score=row.get("similarity_score") or row.get("score"),
        )


class Mapper:
    """Hybrid MITRE ATT&CK mapper with cloud/local routing and RAG retrieval."""

    def __init__(
        self,
        routing_mode: str = ATTACKMapperConfig.ROUTING_MODE,
        cloud_client=None,
        vector_db_client: ActianVectorAIDBClient | None = None,
        embedder=None,
        validator: MitreValidator | None = None,
        mapping_validator: MappingValidator | None = None,
        local_generator=None,
    ):
        normalized_mode = (routing_mode or "").strip().lower()
        if normalized_mode not in {"cloud", "local"}:
            raise ValueError("routing_mode must be 'cloud' or 'local'")

        self.routing_mode = normalized_mode
        self.cloud_client = cloud_client
        self.vector_db_client = vector_db_client or ActianVectorAIDBClient()
        self.embedder = embedder
        self.validator = validator or MitreValidator()
        self.mapping_validator = mapping_validator or MappingValidator()
        self.local_generator = local_generator
        self.local_model = None
        self.local_tokenizer = None
        self.local_runtime_info: dict[str, Any] = {
            "require_cuda": ATTACKMapperConfig.REQUIRE_CUDA,
            "configured_cuda_device": ATTACKMapperConfig.LOCAL_CUDA_DEVICE,
        }
        raw_status = self.vector_db_client.check_collection_ready(
            collection_name=ATTACKMapperConfig.VECTOR_DB_COLLECTION,
            expected_dim=ATTACKMapperConfig.EXPECTED_EMBEDDING_DIM,
            min_vectors=ATTACKMapperConfig.MIN_COLLECTION_VECTORS,
        )
        if isinstance(raw_status, VectorDBReadiness):
            self.vector_db_status = raw_status
        elif isinstance(raw_status, dict):
            self.vector_db_status = VectorDBReadiness.model_validate(raw_status)
        else:
            raise TypeError("check_collection_ready() must return VectorDBReadiness or dict")

        if ATTACKMapperConfig.REQUIRE_RAG and not self.vector_db_status.ready:
            raise VectorDBNotReadyError(
                "Actian VectorAI collection is not ready for RAG "
                f"(reason={self.vector_db_status.reason}, "
                f"address={self.vector_db_status.address}, "
                f"collection={self.vector_db_status.collection}). "
                "Run `python scripts/seed_vector_db.py --attack-corpus "
                "data/corpus/enterprise-attack-18.1.json --mapped-dir data/mapped`, "
                "then verify ATTACK_MAPPER_VECTOR_DB_ADDRESS and "
                "ATTACK_MAPPER_VECTOR_DB_COLLECTION."
            )

        if self.routing_mode == "cloud" and self.cloud_client is None:
            if not ReporterConfig.validate():
                raise ValueError("Reporter configuration validation failed")
            self.cloud_client = google.genai.Client(api_key=ReporterConfig.GEMINI_API_KEY)

    def map_finding(self, finding_report: FindingReport | dict[str, Any]) -> MitreMappingResult:
        """Map a Reporter finding to MITRE ATT&CK techniques."""
        total_start = time.perf_counter()
        report = self._coerce_finding_report(finding_report)

        embed_start = time.perf_counter()
        embedding = self._embed_summary(report.technical_summary)
        embed_ms = (time.perf_counter() - embed_start) * 1000.0

        vector_start = time.perf_counter()
        pool_k = max(ATTACKMapperConfig.VECTOR_DB_TOP_K, ATTACKMapperConfig.RERANK_POOL_K)
        reference_examples = self.vector_db_client.query_similar(
            embedding=embedding,
            top_k=pool_k,
        )
        reference_examples = _rerank_reference_examples(
            report.technical_summary,
            list(reference_examples),
        )[: ATTACKMapperConfig.VECTOR_DB_TOP_K]
        vector_query_ms = (time.perf_counter() - vector_start) * 1000.0

        generate_start = time.perf_counter()
        if self.routing_mode == "local":
            raw_output = self._run_local_mapping(report, reference_examples)
        else:
            raw_output = self._run_cloud_mapping(report, reference_examples)
        generate_ms = (time.perf_counter() - generate_start) * 1000.0

        postprocess_start = time.perf_counter()
        candidate_ids = self._extract_technique_ids(raw_output)

        validation_result = self.mapping_validator.validate(
            candidate_ids=candidate_ids,
            raw_model_output=raw_output,
            technical_summary=report.technical_summary,
        )
        valid_ids = validation_result.accepted_ids
        validation_passed = validation_result.passed

        postprocess_ms = (time.perf_counter() - postprocess_start) * 1000.0
        total_ms = (time.perf_counter() - total_start) * 1000.0

        mapping_agent = "Mistral-7B-LoRA" if self.routing_mode == "local" else "Gemini-2.5-Flash"

        metadata: dict[str, Any] = {
            "source_agent": "Reporter",
            "mapping_agent": mapping_agent,
            "db_context": "Actian-VectorAI",
            "framework": f"{ATTACKMapperConfig.ATTACK_FRAMEWORK} {ATTACKMapperConfig.ATTACK_VERSION}",
            "retrieved_examples": len(reference_examples),
            "validation_gates": validation_result.gate_results,
        }
        if validation_result.issues:
            metadata["validation_issues"] = [
                {"gate": i.gate, "severity": i.severity, "message": i.message, "technique_id": i.technique_id}
                for i in validation_result.issues
            ]
        if validation_result.rejected_ids:
            metadata["rejected_ids"] = validation_result.rejected_ids
        if ATTACKMapperConfig.ENABLE_TIMING:
            metadata["timing_ms"] = {
                "embed_ms": round(embed_ms, 2),
                "vector_query_ms": round(vector_query_ms, 2),
                "generate_ms": round(generate_ms, 2),
                "postprocess_ms": round(postprocess_ms, 2),
                "total_ms": round(total_ms, 2),
            }

        return MitreMappingResult(
            finding_summary=report.technical_summary,
            mitre_ids=valid_ids,
            validation_passed=validation_passed,
            source_metadata=report.source_metadata,
            severity_score=report.severity_score,
            reference_examples=reference_examples,
            raw_model_output=raw_output,
            routing_mode=self.routing_mode,
            metadata=metadata,
        )

    def process_packet(
        self,
        packet_data: dict,
        max_findings: Optional[int] = None,
    ) -> dict:
        """Map every Reporter-enriched finding in a packet to MITRE ATT&CK IDs.

        Mirrors ``Reporter.process_packet()`` so the two can be chained:

            packet = reporter.process_packet(packet)
            packet = mapper.process_packet(packet)

        Each finding receives ``mitre_mapping`` inside its ``metadata`` dict.
        """
        findings = packet_data.get("findings", [])

        if max_findings and len(findings) > max_findings:
            findings = findings[:max_findings]
            print(f"\nMapping first {max_findings} findings (testing mode)...")
        else:
            print(f"\nMapping {len(findings)} findings to MITRE ATT&CK...")

        mapped_count = 0
        skipped_count = 0
        timing_records: list[dict[str, float]] = []

        for index, finding in enumerate(findings, 1):
            metadata = finding.get("metadata") or {}
            technical_summary = metadata.get("technical_summary")

            if not technical_summary:
                skipped_count += 1
                continue

            try:
                result = self.map_finding(finding)
                if "metadata" not in finding:
                    finding["metadata"] = {}
                finding["metadata"]["mitre_mapping"] = {
                    "mitre_ids": result.mitre_ids,
                    "validation_passed": result.validation_passed,
                    "routing_mode": result.routing_mode,
                    "mapping_agent": result.metadata.get("mapping_agent", ""),
                    "db_context": result.metadata.get("db_context", ""),
                    "framework": result.metadata.get("framework", ""),
                    "retrieved_examples": result.metadata.get("retrieved_examples", 0),
                    "raw_model_output": result.raw_model_output,
                    "mapped_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                if ATTACKMapperConfig.ENABLE_TIMING and isinstance(result.metadata.get("timing_ms"), dict):
                    timing_ms = result.metadata["timing_ms"]
                    finding["metadata"]["mitre_mapping"]["timing_ms"] = timing_ms
                    timing_records.append(
                        {
                            "embed_ms": float(timing_ms.get("embed_ms", 0.0)),
                            "vector_query_ms": float(timing_ms.get("vector_query_ms", 0.0)),
                            "generate_ms": float(timing_ms.get("generate_ms", 0.0)),
                            "postprocess_ms": float(timing_ms.get("postprocess_ms", 0.0)),
                            "total_ms": float(timing_ms.get("total_ms", 0.0)),
                        }
                    )
                mapped_count += 1
            except Exception as exc:
                if "metadata" not in finding:
                    finding["metadata"] = {}
                finding["metadata"]["mitre_mapping"] = {
                    "mitre_ids": [],
                    "error": str(exc),
                    "mapped_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                print(f"  WARNING: mapping failed for finding {index}: {exc}")

            if index % 5 == 0 or index == 1:
                print(f"  OK {index}/{len(findings)} findings mapped")

        if "metadata" not in packet_data:
            packet_data["metadata"] = {}

        packet_data["metadata"]["mapper_stats"] = {
            "total_findings_mapped": mapped_count,
            "skipped_no_summary": skipped_count,
            "routing_mode": self.routing_mode,
            "processing_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "framework": f"{ATTACKMapperConfig.ATTACK_FRAMEWORK} {ATTACKMapperConfig.ATTACK_VERSION}",
            "vector_db_status": self.vector_db_status.model_dump(),
        }
        if ATTACKMapperConfig.ENABLE_TIMING:
            packet_data["metadata"]["mapper_stats"]["timing"] = self._summarize_timing_records(timing_records)
        if self.routing_mode == "local":
            packet_data["metadata"]["mapper_stats"]["local_runtime"] = self.get_local_runtime_info()

        return packet_data

    def _summarize_timing_records(self, timing_records: list[dict[str, float]]) -> dict[str, float]:
        """Summarize per-finding timings into run-level metrics."""
        if not timing_records:
            return {
                "count": 0.0,
                "avg_total_ms": 0.0,
                "p95_total_ms": 0.0,
                "max_total_ms": 0.0,
                "avg_embed_ms": 0.0,
                "avg_vector_query_ms": 0.0,
                "avg_generate_ms": 0.0,
                "avg_postprocess_ms": 0.0,
            }

        total_values = sorted(record.get("total_ms", 0.0) for record in timing_records)
        summary: dict[str, float] = {
            "count": float(len(timing_records)),
            "avg_total_ms": round(sum(total_values) / len(total_values), 2),
            "p95_total_ms": round(self._interpolate_percentile(total_values, 95.0), 2),
            "max_total_ms": round(total_values[-1], 2),
        }
        for stage_name in ("embed_ms", "vector_query_ms", "generate_ms", "postprocess_ms"):
            stage_values = [record.get(stage_name, 0.0) for record in timing_records]
            summary[f"avg_{stage_name}"] = round(sum(stage_values) / len(stage_values), 2)

        return summary

    @staticmethod
    def _interpolate_percentile(sorted_values: list[float], percentile: float) -> float:
        """Compute a percentile on an already sorted list."""
        if not sorted_values:
            return 0.0
        if len(sorted_values) == 1:
            return sorted_values[0]

        position = (percentile / 100.0) * (len(sorted_values) - 1)
        lower_index = int(position)
        upper_index = min(lower_index + 1, len(sorted_values) - 1)
        weight = position - lower_index
        lower_value = sorted_values[lower_index]
        upper_value = sorted_values[upper_index]
        return lower_value + (upper_value - lower_value) * weight

    def save_mapped_packet(self, packet_data: dict, output_dir: str | Path) -> Optional[Path]:
        """Save the fully mapped packet to disk."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        source_file = packet_data.get("source_file", "unknown")
        clean_name = Path(source_file).stem
        output_file = output_dir / f"{clean_name}_mapped_{timestamp}.json"

        try:
            with open(output_file, "w", encoding="utf-8") as handle:
                json.dump(packet_data, handle, indent=2)
            print(f"Saved mapped packet to: {output_file.name}")
            return output_file
        except Exception as exc:
            print(f"ERROR: saving mapped packet failed: {exc}")
            return None

    def _coerce_finding_report(self, finding_report: FindingReport | dict[str, Any]) -> FindingReport:
        """Accept a FindingReport, a top-level dict with ``technical_summary``,
        or a Reporter-enriched finding dict (summary inside ``metadata``)."""
        if isinstance(finding_report, FindingReport):
            return finding_report

        if not isinstance(finding_report, dict):
            raise TypeError("finding_report must be a FindingReport or dict")

        metadata = finding_report.get("metadata") or {}

        technical_summary = (
            finding_report.get("technical_summary")
            or metadata.get("technical_summary")
        )
        if not technical_summary:
            raise ValueError(
                "Cannot coerce finding to FindingReport: "
                "no technical_summary found at top level or inside metadata"
            )

        source_metadata = finding_report.get("source_metadata") or {
            key: value
            for key, value in {
                "hostname": metadata.get("hostname") or finding_report.get("hostname"),
                "log_source": metadata.get("log_source") or finding_report.get("log_source"),
                "source_ip": finding_report.get("source_ip"),
                "destination_ip": finding_report.get("destination_ip"),
            }.items()
            if value is not None
        }

        payload = {
            "technical_summary": technical_summary,
            "source_metadata": source_metadata,
            "severity_score": finding_report.get("severity_score", finding_report.get("cvss_score")),
            "title": finding_report.get("title", ""),
            "cve_ids": finding_report.get("cve_ids") or [],
            "services": metadata.get("services") or [],
            "ports": metadata.get("ports") or [],
        }

        return FindingReport.model_validate(payload)

    def _get_embedder(self):
        """Lazily load the sentence transformer embedder."""
        if self.embedder is not None:
            return self.embedder

        try:
            import torch
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "sentence-transformers is required for RAG retrieval. "
                "Install the mapper dependencies before using Mapper."
            ) from exc

        cuda_available = torch.cuda.is_available()
        configured_device = ATTACKMapperConfig.LOCAL_CUDA_DEVICE
        embedder_device = "cpu"

        if cuda_available:
            device_count = torch.cuda.device_count()
            if configured_device >= device_count:
                raise RuntimeError(
                    "Configured ATTACK_MAPPER_LOCAL_CUDA_DEVICE is out of range for available GPUs "
                    f"(configured={configured_device}, available={device_count})."
                )
            embedder_device = f"cuda:{configured_device}"
        elif self.routing_mode == "local" and ATTACKMapperConfig.REQUIRE_CUDA:
            raise RuntimeError(
                "CUDA is required for local mapper mode but is not available. "
                "Install a CUDA-enabled PyTorch build or set ATTACK_MAPPER_REQUIRE_CUDA=false."
            )

        self.embedder = SentenceTransformer(ATTACKMapperConfig.EMBEDDING_MODEL, device=embedder_device)
        self.local_runtime_info["embedder_device"] = embedder_device
        return self.embedder

    def _embed_summary(self, technical_summary: str) -> list[float]:
        """Vectorize the upstream technical summary."""
        embedder = self._get_embedder()
        embedding = embedder.encode(technical_summary)

        if hasattr(embedding, "tolist"):
            return embedding.tolist()
        if isinstance(embedding, list):
            return embedding
        return list(embedding)

    def _format_db_results(self, reference_examples: list[ReferenceExample]) -> str:
        """Format retrieved examples for prompt injection."""
        if not reference_examples:
            return "No verified historical examples were found."

        lines = []
        for index, example in enumerate(reference_examples, 1):
            mitre_ids = ", ".join(example.mitre_ids) if example.mitre_ids else "None"
            score_suffix = ""
            if example.similarity_score is not None:
                score_suffix = f" (similarity={example.similarity_score:.3f})"
            lines.append(
                f"{index}. Summary: {example.technical_summary}\n"
                f"   Verified MITRE IDs: {mitre_ids}{score_suffix}"
            )

        return "\n".join(lines)

    def _run_cloud_mapping(self, report: FindingReport, reference_examples: list[ReferenceExample]) -> str:
        """Map using Gemini 2.5 Flash."""
        prompt = AttackMapperPrompts.CLOUD_RAG_USER_PROMPT_TEMPLATE.format(
            db_results=self._format_db_results(reference_examples),
            technical_summary=report.technical_summary,
            title=report.title or "N/A",
            cves=", ".join(report.cve_ids) if report.cve_ids else "N/A",
            services=", ".join(report.services) if report.services else "N/A",
            ports=", ".join(report.ports) if report.ports else "N/A",
            severity_score=report.severity_score if report.severity_score is not None else "N/A",
            source_metadata=json.dumps(report.source_metadata, sort_keys=True),
        )

        from google.genai import types

        fallbacks = parse_gemini_fallback_models()
        models = [ATTACKMapperConfig.CLOUD_MODEL] + fallbacks

        def _per_model(mid: str):
            r = self.cloud_client.models.generate_content(
                model=mid,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=AttackMapperPrompts.SYSTEM_PROMPT,
                    temperature=0.1,
                    top_p=0.9,
                    max_output_tokens=300,
                    thinking_config=types.ThinkingConfig(thinking_budget=0),
                ),
            )
            return (r.text or "").strip()

        return invoke_with_transient_retry(
            per_model=_per_model,
            models=models,
            allow_fallback=bool(fallbacks),
        )

    def _run_local_mapping(self, report: FindingReport, reference_examples: list[ReferenceExample]) -> str:
        """Map using the local fine-tuned Mistral-7B LoRA adapter.

        The prompt matches the RAG-aware template used during v2 LoRA
        fine-tuning (### Instruction / ### Reference Examples from Database /
        ### Log / ### Response).
        """
        prompt = AttackMapperPrompts.LOCAL_USER_PROMPT_TEMPLATE.format(
            db_results=self._format_db_results(reference_examples),
            technical_summary=report.technical_summary,
        )

        self._get_local_generator()

        # Backward compatibility for injected fake generators used in tests.
        if self.local_model is None or self.local_tokenizer is None:
            generator = self.local_generator
            if callable(generator):
                generated = generator(prompt)
                if isinstance(generated, str):
                    return generated.strip()
                if isinstance(generated, list) and generated:
                    first = generated[0]
                    if isinstance(first, dict):
                        text = first.get("generated_text", "")
                        return text.replace(prompt, "", 1).strip() if text.startswith(prompt) else text.strip()
            raise TypeError("Local generator returned an unsupported response type")

        import torch

        tokenizer = self.local_tokenizer
        model = self.local_model
        tokenized_inputs = tokenizer(prompt, return_tensors="pt")

        if torch.cuda.is_available():
            target_device = torch.device(f"cuda:{ATTACKMapperConfig.LOCAL_CUDA_DEVICE}")
        else:
            target_device = torch.device("cpu")
        tokenized_inputs = {key: value.to(target_device) for key, value in tokenized_inputs.items()}

        stopping_criteria = _LocalDecodingGuards.create_stopping_criteria(tokenizer)
        logits_processor = _LocalDecodingGuards.create_logits_processor(tokenizer)

        with torch.inference_mode():
            output_tokens = model.generate(
                **tokenized_inputs,
                max_new_tokens=ATTACKMapperConfig.LOCAL_MAX_NEW_TOKENS,
                do_sample=False,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
                stopping_criteria=stopping_criteria,
                logits_processor=logits_processor,
            )

        prompt_token_count = len(tokenized_inputs["input_ids"][0])
        new_tokens = output_tokens[0][prompt_token_count:]
        return tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

    def _get_local_generator(self):
        """Lazily load the local Mistral-7B LoRA generator."""
        if self.local_model is not None and self.local_tokenizer is not None:
            return self.local_model

        # If a custom local generator was injected, keep existing behavior.
        if self.local_generator is not None and self.local_model is None and self.local_tokenizer is None:
            return self.local_generator

        try:
            import torch
        except ImportError as exc:
            raise ImportError("torch is required for local mapper mode.") from exc

        cuda_available = torch.cuda.is_available()
        configured_device = ATTACKMapperConfig.LOCAL_CUDA_DEVICE
        self.local_runtime_info["cuda_available"] = cuda_available

        if ATTACKMapperConfig.REQUIRE_CUDA and not cuda_available:
            raise RuntimeError(
                "CUDA is required for local mapper mode but no CUDA device is available. "
                "Set ATTACK_MAPPER_REQUIRE_CUDA=false to allow fallback behavior."
            )

        if cuda_available:
            device_count = torch.cuda.device_count()
            if configured_device >= device_count:
                raise RuntimeError(
                    "Configured ATTACK_MAPPER_LOCAL_CUDA_DEVICE is out of range for available GPUs "
                    f"(configured={configured_device}, available={device_count})."
                )

        try:
            from peft import PeftModel
            from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        except ImportError as exc:
            raise ImportError(
                "transformers, peft, and torch are required for local mapper mode."
            ) from exc

        if cuda_available:
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=torch.float16,
            )
            device_map: dict[str, int] | str = {"": configured_device}
        else:
            quantization_config = None
            device_map = "cpu"
            print("Warning: CUDA unavailable. Loading local mapper model on CPU.")

        print(f"Loading base model: {ATTACKMapperConfig.LOCAL_BASE_MODEL}")
        tokenizer = AutoTokenizer.from_pretrained(ATTACKMapperConfig.LOCAL_BASE_MODEL)
        model_kwargs: dict[str, Any] = {"device_map": device_map}
        if quantization_config is not None:
            model_kwargs["quantization_config"] = quantization_config
        base_model = AutoModelForCausalLM.from_pretrained(ATTACKMapperConfig.LOCAL_BASE_MODEL, **model_kwargs)

        # FIX: Resolve Windows path to POSIX-style (forward slashes) for PEFT
        adapter_path = ATTACKMapperConfig.LOCAL_ADAPTER_PATH.resolve().as_posix()
        print(f"Attaching LoRA adapter from: {adapter_path}")
        
        adapter_model = PeftModel.from_pretrained(
            base_model,
            adapter_path,
        )

        parameter_device = str(next(adapter_model.parameters()).device)
        self.local_runtime_info["model_parameter_device"] = parameter_device
        self.local_runtime_info["generator_device_map"] = str(device_map)
        if cuda_available:
            self.local_runtime_info["cuda_device_name"] = torch.cuda.get_device_name(configured_device)

        if ATTACKMapperConfig.REQUIRE_CUDA:
            expected_device = f"cuda:{configured_device}"
            if parameter_device != expected_device:
                raise RuntimeError(
                    "Local mapper model did not load on the configured CUDA device "
                    f"(expected={expected_device}, got={parameter_device})."
                )

        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        if tokenizer.pad_token_id is None:
            tokenizer.pad_token_id = tokenizer.eos_token_id

        # Avoid generation-config warning churn when max_new_tokens is supplied at call-time.
        generation_config = getattr(adapter_model, "generation_config", None)
        if generation_config is not None:
            generation_config.max_length = None
            generation_config.temperature = None

        self.local_model = adapter_model
        self.local_tokenizer = tokenizer
        # Keep this marker for compatibility checks and runtime introspection.
        self.local_generator = "direct_generate"
        self.local_runtime_info["generation_backend"] = "direct_generate"
        self.local_runtime_info["max_new_tokens"] = ATTACKMapperConfig.LOCAL_MAX_NEW_TOKENS
        return self.local_model

    def get_local_runtime_info(self) -> dict[str, Any]:
        """Return local runtime/device information for diagnostics."""
        info = dict(self.local_runtime_info)
        info.setdefault("require_cuda", ATTACKMapperConfig.REQUIRE_CUDA)
        info.setdefault("configured_cuda_device", ATTACKMapperConfig.LOCAL_CUDA_DEVICE)

        try:
            import torch
        except ImportError:
            info.setdefault("cuda_available", False)
            return info

        cuda_available = torch.cuda.is_available()
        info.setdefault("cuda_available", cuda_available)
        if cuda_available:
            device_count = torch.cuda.device_count()
            info.setdefault("cuda_device_count", device_count)
            configured_device = ATTACKMapperConfig.LOCAL_CUDA_DEVICE
            if configured_device < device_count:
                info.setdefault("cuda_device_name", torch.cuda.get_device_name(configured_device))

        return info

    def _extract_technique_ids(self, raw_output: str) -> list[str]:
        """Extract candidate technique IDs from model output.

        Handles three output formats in priority order:
        1. Python list literal from local LoRA: ``['T1059', 'T1110']``
        2. JSON object from cloud model: ``{"techniques": [{"id": "T1059"}]}``
        3. Regex fallback: any ``T\\d{4}`` pattern found in free text
        """
        if not raw_output:
            return []

        candidates: list[str] = []
        stripped = raw_output.strip()

        # Truncate at first ']' to discard any rambling after the list.
        bracket_pos = stripped.find("]")
        if bracket_pos != -1:
            stripped = stripped[: bracket_pos + 1]

        # 1. Try Python list literal (ast.literal_eval handles single-quoted strings).
        import ast
        try:
            parsed_list = ast.literal_eval(stripped)
            if isinstance(parsed_list, list):
                for item in parsed_list:
                    candidates.append(str(item).strip())
        except (ValueError, SyntaxError):
            pass

        # 2. Try JSON object (cloud model schema).
        if not candidates:
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                parsed = None

            if isinstance(parsed, dict):
                techniques = parsed.get("techniques") or []
                for item in techniques:
                    if isinstance(item, dict) and item.get("id"):
                        candidates.append(str(item["id"]))
                direct_ids = parsed.get("mitre_ids") or []
                if isinstance(direct_ids, list):
                    candidates.extend(str(item) for item in direct_ids)

            if isinstance(parsed, list):
                for item in parsed:
                    candidates.append(str(item).strip())

        # 3. Regex fallback for any T-IDs in free text.
        if not candidates:
            candidates.extend(
                re.findall(r"\bT\d{4}(?:\.\d{3})?\b", stripped, flags=re.IGNORECASE)
            )

        unique_candidates: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            normalized = candidate.upper()
            if normalized in seen:
                continue
            seen.add(normalized)
            unique_candidates.append(normalized)

        return unique_candidates
