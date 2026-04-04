"""Remediation generator: ATT&CK ID + client context -> vendor-tailored steps.

Uses Gemini structured output to produce a RemediationOutput grounded in
the controls retrieved by Section 3 correlation.  The Self-RAG verification
loop (selfrag.py) wraps this generator and retries on verification failure.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from langchain_google_genai import ChatGoogleGenerativeAI

from src.section4_remediation import config
from src.section4_remediation.prompts import REMEDIATION_PROMPT, RETRY_PROMPT
from src.section4_remediation.schemas import RemediationOutput, VerificationResult

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


def generate_remediation(
    finding: dict[str, Any],
    correlation: dict[str, Any],
    tech_stack: list[str] | None = None,
    *,
    rejection_issues: str | None = None,
) -> RemediationOutput:
    """Call Gemini to produce structured remediation for a single finding.

    Parameters
    ----------
    finding : dict
        The raw finding dict (must contain ``metadata``).
    correlation : dict
        The ``metadata.rag_correlation`` block from the correlated JSON.
    tech_stack : list[str] | None
        Override for ``GLOBAL_TECH_STACK``.
    rejection_issues : str | None
        If set, the retry prompt is used with these rejection reasons.
    """
    meta = finding.get("metadata") or {}
    summary = meta.get("technical_summary", "")
    severity = finding.get("severity", "medium")
    mitre_mapping = meta.get("mitre_mapping") or {}
    mitre_ids = mitre_mapping.get("mitre_ids", [])

    stack = tech_stack or config.GLOBAL_TECH_STACK
    controls_text, _control_ids = _format_controls_text(correlation)

    prompt_vars = {
        "technical_summary": summary,
        "severity": severity,
        "mitre_ids": ", ".join(mitre_ids) if mitre_ids else "none",
        "tech_stack": ", ".join(stack),
        "controls_text": controls_text,
    }

    llm = _get_llm()
    structured = llm.with_structured_output(RemediationOutput)

    if rejection_issues:
        prompt_vars["rejection_issues"] = rejection_issues
        chain = RETRY_PROMPT | structured
    else:
        chain = REMEDIATION_PROMPT | structured

    result: RemediationOutput = chain.invoke(prompt_vars)
    return result


def build_remediation_metadata(
    output: RemediationOutput,
    verification: VerificationResult,
) -> dict[str, Any]:
    """Serialize generator + verifier results into the JSON metadata block."""
    return {
        "steps": [s.model_dump() for s in output.steps],
        "priority": output.priority,
        "estimated_effort": output.estimated_effort,
        "prerequisites": output.prerequisites,
        "verification_procedure": output.verification,
        "source_control_ids": output.source_control_ids,
        "model": config.GEMINI_MODEL,
        "prompt_version": config.PROMPT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "selfrag_verification": {
            "grounding_score": verification.grounding_score,
            "relevance_score": verification.relevance_score,
            "completeness_score": verification.completeness_score,
            "passed": verification.passed,
            "issues": [i.model_dump() for i in verification.issues],
            "attempts": verification.attempts,
        },
    }
