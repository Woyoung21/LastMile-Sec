"""Remediation generator: ATT&CK ID + client context -> vendor-tailored steps.

Uses Gemini structured output. Optional branch binds ``google_search`` for vendor UI.
Self-RAG (selfrag.py) wraps generation and retries on verification failure.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from langchain_google_genai import ChatGoogleGenerativeAI

from src.section4_remediation import config
from src.section4_remediation.grounding_serialization import json_safe_grounding_metadata
from src.section4_remediation.prompts import (
    REMEDIATION_PROMPT,
    REMEDIATION_PROMPT_WITH_SEARCH,
    RETRY_PROMPT,
    RETRY_PROMPT_WITH_SEARCH,
)
from src.section4_remediation.schemas import RemediationOutput, RemediationProvenance, VerificationResult

_LLM: ChatGoogleGenerativeAI | None = None


def _get_llm() -> ChatGoogleGenerativeAI:
    global _LLM
    if _LLM is None:
        if not config.GOOGLE_API_KEY:
            raise RuntimeError("GOOGLE_API_KEY is not set (see .env.example).")
        _LLM = ChatGoogleGenerativeAI(
            model=config.GEMINI_MODEL,
            google_api_key=config.GOOGLE_API_KEY,
            temperature=config.LLM_TEMPERATURE,
        )
    return _LLM


def _format_controls_text(correlation: dict[str, Any]) -> tuple[str, list[str]]:
    """Build a human-readable block of source controls and collect their IDs."""
    parts: list[str] = []
    control_ids: list[str] = []

    best = correlation.get("best_control")
    if best:
        cid = best.get("control_id", "unknown")
        control_ids.append(cid)
        parts.append(
            f"[BEST MATCH] Control: {cid}\n"
            f"  Vendor/Product: {best.get('vendor_product', 'N/A')}\n"
            f"  Remediation: {best.get('remediation_steps', 'N/A')}\n"
            f"  Audit: {best.get('audit_procedure', 'N/A')}"
        )

    for bucket_key in ("vendor_controls", "framework_controls"):
        for cand in correlation.get(bucket_key, []):
            ctrl = cand.get("control") or {}
            cid = ctrl.get("control_id", "unknown")
            if cid in control_ids:
                continue
            control_ids.append(cid)
            parts.append(
                f"Control: {cid}\n"
                f"  Vendor/Product: {ctrl.get('vendor_product', 'N/A')}\n"
                f"  Remediation: {ctrl.get('remediation_steps', 'N/A')}\n"
                f"  Audit: {ctrl.get('audit_procedure', 'N/A')}"
            )

    return "\n\n".join(parts) if parts else "(no source controls available)", control_ids


def _parse_structured_invoke(
    raw_result: Any,
) -> tuple[RemediationOutput, dict[str, Any] | None]:
    """Extract Pydantic output and optional grounding_metadata from LangChain invoke."""
    if isinstance(raw_result, RemediationOutput):
        return raw_result, None

    if isinstance(raw_result, dict) and "parsed" in raw_result:
        parsed = raw_result["parsed"]
        if not isinstance(parsed, RemediationOutput):
            msg = f"Expected RemediationOutput, got {type(parsed)}"
            raise TypeError(msg)
        raw_msg = raw_result.get("raw")
        gmeta = None
        if raw_msg is not None and hasattr(raw_msg, "response_metadata"):
            meta = getattr(raw_msg, "response_metadata", None) or {}
            gmeta = meta.get("grounding_metadata")
        return parsed, gmeta

    raise TypeError(f"Unexpected structured output type: {type(raw_result)}")


def _chain_for_mode(*, use_search: bool, retry: bool):
    llm = _get_llm()
    if use_search:
        bound = llm.bind_tools([{"google_search": {}}])
        structured = bound.with_structured_output(
            RemediationOutput,
            method="json_schema",
            include_raw=True,
        )
        prompt = RETRY_PROMPT_WITH_SEARCH if retry else REMEDIATION_PROMPT_WITH_SEARCH
    else:
        structured = llm.with_structured_output(
            RemediationOutput,
            method="json_schema",
            include_raw=True,
        )
        prompt = RETRY_PROMPT if retry else REMEDIATION_PROMPT

    return prompt | structured


def generate_remediation(
    finding: dict[str, Any],
    correlation: dict[str, Any],
    tech_stack: list[str] | None = None,
    *,
    rejection_issues: str | None = None,
    use_search: bool = False,
    search_trigger_reason: str | None = None,
) -> tuple[RemediationOutput, RemediationProvenance]:
    """Call Gemini to produce structured remediation for a single finding.

    Returns
    -------
    RemediationOutput
        Parsed remediation.
    RemediationProvenance
        Whether search grounding was used and any grounding metadata from the API.
    """
    meta = finding.get("metadata") or {}
    summary = meta.get("technical_summary", "")
    severity = finding.get("severity", "medium")
    mitre_mapping = meta.get("mitre_mapping") or {}
    mitre_ids = mitre_mapping.get("mitre_ids", [])

    stack = tech_stack or config.GLOBAL_TECH_STACK
    controls_text, _control_ids = _format_controls_text(correlation)

    prompt_vars: dict[str, str] = {
        "technical_summary": summary,
        "severity": severity,
        "mitre_ids": ", ".join(mitre_ids) if mitre_ids else "none",
        "tech_stack": ", ".join(stack),
        "controls_text": controls_text,
    }

    retry = bool(rejection_issues)
    if retry:
        prompt_vars["rejection_issues"] = rejection_issues or ""

    chain = _chain_for_mode(use_search=use_search, retry=retry)
    raw_result = chain.invoke(prompt_vars)
    output, g_raw = _parse_structured_invoke(raw_result)

    if use_search:
        provenance = RemediationProvenance(
            mode="graph_plus_search",
            search_trigger_reason=search_trigger_reason,
            grounding_metadata=json_safe_grounding_metadata(g_raw),
        )
    else:
        provenance = RemediationProvenance(
            mode="graph_only",
            search_trigger_reason=None,
            grounding_metadata=json_safe_grounding_metadata(g_raw),
        )

    return output, provenance


def build_remediation_metadata(
    output: RemediationOutput,
    verification: VerificationResult,
    provenance: RemediationProvenance,
) -> dict[str, Any]:
    """Serialize generator + verifier results into the JSON metadata block."""
    return {
        "executive_summary": output.executive_summary,
        "limitations": list(output.limitations),
        "steps": [s.model_dump() for s in output.steps],
        "priority": output.priority,
        "estimated_effort": output.estimated_effort,
        "prerequisites": output.prerequisites,
        "verification_procedure": output.verification,
        "source_control_ids": output.source_control_ids,
        "provenance": provenance.model_dump(exclude_none=True),
        "model": config.GEMINI_MODEL,
        "prompt_version": config.PROMPT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "selfrag_verification": {
            "grounding_score": verification.grounding_score,
            "relevance_score": verification.relevance_score,
            "completeness_score": verification.completeness_score,
            "substep_quality_score": verification.substep_quality_score,
            "passed": verification.passed,
            "issues": [i.model_dump() for i in verification.issues],
            "attempts": verification.attempts,
        },
    }
