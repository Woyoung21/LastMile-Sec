"""
Hybrid, RAG-enhanced MITRE ATT&CK mapper for Section 2.

This mapper consumes Reporter output, retrieves similar historical examples
from Actian VectorAI, and routes mapping through either Gemini or a local
Mistral-7B LoRA adapter.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import google.genai
from pydantic import BaseModel, Field

from .config import ATTACKMapperConfig, ReporterConfig
from .prompts import AttackMapperPrompts


class FindingReport(BaseModel):
    """Normalized input expected from the upstream Reporter Agent."""

    technical_summary: str = Field(..., min_length=1)
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    severity_score: float | None = Field(default=None, ge=0.0, le=10.0)


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


class ActianVectorAIDBClient:
    """Actian VectorAI client wrapper backed by the cortex library."""

    def __init__(self, client=None, cortex_error_cls=None):
        self._distance_metric = None
        self._cortex_error_cls = cortex_error_cls

        if client is not None:
            self.client = client
            if self._cortex_error_cls is None:
                self._cortex_error_cls = Exception
            return

        from cortex import CortexClient, CortexError, DistanceMetric

        self.client = CortexClient(address=ATTACKMapperConfig.VECTOR_DB_ADDRESS)
        self._distance_metric = getattr(DistanceMetric, "COSINE", None)
        self._cortex_error_cls = CortexError

    def query_similar(self, embedding: list[float], top_k: int = ATTACKMapperConfig.VECTOR_DB_TOP_K) -> list[ReferenceExample]:
        """Return the top-k similar historical examples."""
        if self.client is None:
            return []

        try:
            rows = self.client.search(
                collection_name=ATTACKMapperConfig.VECTOR_DB_COLLECTION,
                query=embedding,
                top_k=top_k,
                with_payload=True,
            )
        except self._cortex_error_cls:
            return []

        return [self._normalize_row(row) for row in rows[:top_k]]

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
        self.local_generator = local_generator

        if self.routing_mode == "cloud" and self.cloud_client is None:
            if not ReporterConfig.validate():
                raise ValueError("Reporter configuration validation failed")
            self.cloud_client = google.genai.Client(api_key=ReporterConfig.GEMINI_API_KEY)

    def map_finding(self, finding_report: FindingReport | dict[str, Any]) -> MitreMappingResult:
        """Map a Reporter finding to MITRE ATT&CK techniques."""
        report = self._coerce_finding_report(finding_report)
        embedding = self._embed_summary(report.technical_summary)
        reference_examples = self.vector_db_client.query_similar(
            embedding=embedding,
            top_k=ATTACKMapperConfig.VECTOR_DB_TOP_K,
        )

        if self.routing_mode == "local":
            raw_output = self._run_local_mapping(report, reference_examples)
        else:
            raw_output = self._run_cloud_mapping(report, reference_examples)

        candidate_ids = self._extract_technique_ids(raw_output)
        valid_ids = self.validator.validate_many(candidate_ids)

        mapping_agent = "Mistral-7B-LoRA" if self.routing_mode == "local" else "Gemini-2.5-Flash"
        validation_passed = bool(candidate_ids) and len(candidate_ids) == len(valid_ids)
        if not candidate_ids:
            validation_passed = True

        return MitreMappingResult(
            finding_summary=report.technical_summary,
            mitre_ids=valid_ids,
            validation_passed=validation_passed,
            source_metadata=report.source_metadata,
            severity_score=report.severity_score,
            reference_examples=reference_examples,
            raw_model_output=raw_output,
            routing_mode=self.routing_mode,
            metadata={
                "source_agent": "Reporter",
                "mapping_agent": mapping_agent,
                "db_context": "Actian-VectorAI",
                "framework": f"{ATTACKMapperConfig.ATTACK_FRAMEWORK} {ATTACKMapperConfig.ATTACK_VERSION}",
                "retrieved_examples": len(reference_examples),
            },
        )

    def _coerce_finding_report(self, finding_report: FindingReport | dict[str, Any]) -> FindingReport:
        """Accept either a FindingReport or equivalent Reporter JSON."""
        if isinstance(finding_report, FindingReport):
            return finding_report

        if not isinstance(finding_report, dict):
            raise TypeError("finding_report must be a FindingReport or dict")

        if "technical_summary" in finding_report:
            payload = finding_report
        else:
            metadata = finding_report.get("metadata") or {}
            payload = {
                "technical_summary": metadata.get("technical_summary") or finding_report.get("technical_summary"),
                "source_metadata": finding_report.get("source_metadata")
                or {
                    key: value
                    for key, value in {
                        "hostname": metadata.get("hostname") or finding_report.get("hostname"),
                        "log_source": metadata.get("log_source") or finding_report.get("log_source"),
                        "source_ip": finding_report.get("source_ip"),
                        "destination_ip": finding_report.get("destination_ip"),
                    }.items()
                    if value is not None
                },
                "severity_score": finding_report.get("severity_score", finding_report.get("cvss_score")),
            }

        return FindingReport.model_validate(payload)

    def _get_embedder(self):
        """Lazily load the sentence transformer embedder."""
        if self.embedder is not None:
            return self.embedder

        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "sentence-transformers is required for RAG retrieval. "
                "Install the mapper dependencies before using Mapper."
            ) from exc

        self.embedder = SentenceTransformer(ATTACKMapperConfig.EMBEDDING_MODEL)
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
            severity_score=report.severity_score if report.severity_score is not None else "N/A",
            source_metadata=json.dumps(report.source_metadata, sort_keys=True),
        )

        response = self.cloud_client.models.generate_content(
            model=ATTACKMapperConfig.CLOUD_MODEL,
            contents=prompt,
            config={
                "system_instruction": AttackMapperPrompts.SYSTEM_PROMPT,
                "temperature": 0.1,
                "top_p": 0.9,
                "max_output_tokens": 300,
            },
        )

        return (response.text or "").strip()

    def _run_local_mapping(self, report: FindingReport, reference_examples: list[ReferenceExample]) -> str:
        """Map using the local fine-tuned Mistral LoRA adapter."""
        prompt = AttackMapperPrompts.LOCAL_USER_PROMPT_TEMPLATE.format(
            db_results=self._format_db_results(reference_examples),
            technical_summary=report.technical_summary,
        )

        generator = self._get_local_generator()
        generated = generator(prompt)

        if isinstance(generated, str):
            return generated.strip()
        if isinstance(generated, list) and generated:
            first = generated[0]
            if isinstance(first, dict):
                text = first.get("generated_text", "")
                return text.replace(prompt, "", 1).strip() if text.startswith(prompt) else text.strip()
        raise TypeError("Local generator returned an unsupported response type")

    def _get_local_generator(self):
        """Lazily load the local Mistral-7B LoRA generator."""
        if self.local_generator is not None:
            return self.local_generator

        try:
            import torch
            from peft import PeftModel
            from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, pipeline
        except ImportError as exc:
            raise ImportError(
                "transformers, peft, and torch are required for local mapper mode."
            ) from exc

        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.float16,
        )

        tokenizer = AutoTokenizer.from_pretrained(ATTACKMapperConfig.LOCAL_BASE_MODEL)
        base_model = AutoModelForCausalLM.from_pretrained(
            ATTACKMapperConfig.LOCAL_BASE_MODEL,
            quantization_config=quantization_config,
            device_map="auto",
        )
        adapter_model = PeftModel.from_pretrained(
            base_model,
            str(ATTACKMapperConfig.LOCAL_ADAPTER_PATH),
        )

        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        self.local_generator = pipeline(
            "text-generation",
            model=adapter_model,
            tokenizer=tokenizer,
            max_new_tokens=128,
            do_sample=False,
        )
        return self.local_generator

    def _extract_technique_ids(self, raw_output: str) -> list[str]:
        """Extract candidate technique IDs from model output."""
        if not raw_output:
            return []

        candidates: list[str] = []

        stripped = raw_output.strip()
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

        candidates.extend(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", stripped, flags=re.IGNORECASE))

        unique_candidates: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            normalized = candidate.upper()
            if normalized in seen:
                continue
            seen.add(normalized)
            unique_candidates.append(normalized)

        return unique_candidates
