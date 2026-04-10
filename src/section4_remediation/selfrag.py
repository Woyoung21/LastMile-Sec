"""Self-RAG verification layer for generated remediation.

Implements four checks:
  1. Grounding       — are the generated steps supported by source control text?
  2. Relevance       — do the steps address the finding's summary and MITRE techniques?
  3. Completeness    — do the steps reference top-ranked correlated controls?
  4. Substep quality — do steps have sufficient substeps, breadcrumbs, and confirmation hints?

If verification fails, the caller (generate_with_verification in this module)
re-invokes the generator with augmented rejection feedback.
"""

from __future__ import annotations

import re
from typing import Any

from langchain_google_genai import ChatGoogleGenerativeAI

from src.section4_remediation import config
from src.section4_remediation.generator import (
    _format_controls_text,
    generate_remediation,
)
from src.section4_remediation.grounding_serialization import grounding_metadata_to_source_blob
from src.section4_remediation.prompts import GROUNDING_CHECK_PROMPT
from src.section4_remediation.retrieval_policy import should_augment_with_search
from src.section4_remediation.schemas import (
    RemediationOutput,
    RemediationProvenance,
    VerificationIssue,
    VerificationResult,
)

_STOPWORDS = frozenset(
    "a an the is are was were be been being have has had do does did will would "
    "shall should may might can could of in to for on with at by from as into "
    "through during before after above below between out off over under again "
    "further then once that this these those it its and but or nor not no so if "
    "all any both each few more most other some such very just also how when where "
    "which who whom what why set ensure configure disable enable".split()
)

_JUDGE_LLM: ChatGoogleGenerativeAI | None = None


def _get_judge_llm() -> ChatGoogleGenerativeAI:
    global _JUDGE_LLM
    if _JUDGE_LLM is None:
        if not config.GOOGLE_API_KEY:
            raise RuntimeError("GOOGLE_API_KEY is not set (see .env.example).")
        _JUDGE_LLM = ChatGoogleGenerativeAI(
            model=config.GEMINI_MODEL,
            google_api_key=config.GOOGLE_API_KEY,
            temperature=0.0,
        )
    return _JUDGE_LLM


def _token_set(text: str) -> set[str]:
    return {
        w
        for w in re.findall(r"[a-z0-9\\/.]+", text.lower())
        if len(w) > 2 and w not in _STOPWORDS
    }


# ------------------------------------------------------------------
# Check 1: Grounding
# ------------------------------------------------------------------

def _heuristic_grounding(
    output: RemediationOutput,
    source_text: str,
) -> tuple[float, list[VerificationIssue]]:
    """Token-overlap grounding score: fraction of steps with non-empty overlap."""
    issues: list[VerificationIssue] = []
    if not output.steps:
        return 0.0, [VerificationIssue(
            check="grounding", severity="error", message="No steps generated."
        )]

    source_tokens = _token_set(source_text)
    grounded_count = 0

    for step in output.steps:
        sub = " ".join(step.substeps) if step.substeps else ""
        step_text = (
            f"{step.title} {step.command_or_action} {step.explanation} "
            f"{step.ui_breadcrumb or ''} {step.step_type or ''} {sub}"
        )
        step_tokens = _token_set(step_text)
        overlap = step_tokens & source_tokens
        if overlap:
            grounded_count += 1
        else:
            issues.append(VerificationIssue(
                check="grounding",
                severity="warning",
                message=f"Step {step.step_number} ('{step.title}') has no token overlap with source controls.",
            ))

    score = grounded_count / len(output.steps)
    return score, issues


def _llm_judge_grounding(
    output: RemediationOutput,
    source_text: str,
) -> tuple[float, list[VerificationIssue]]:
    """LLM-as-judge grounding: ask Gemini if each step is supported."""
    issues: list[VerificationIssue] = []
    if not output.steps:
        return 0.0, [VerificationIssue(
            check="grounding", severity="error", message="No steps to judge."
        )]

    llm = _get_judge_llm()
    chain = GROUNDING_CHECK_PROMPT | llm
    supported = 0

    for step in output.steps:
        resp = chain.invoke({
            "source_text": source_text,
            "step_title": step.title,
            "step_action": step.command_or_action,
            "step_breadcrumb": step.ui_breadcrumb or "N/A",
            "step_substeps": "\n".join(f"  - {s}" for s in step.substeps) if step.substeps else "N/A",
            "step_explanation": step.explanation,
        })
        verdict_text = resp.content.strip().upper() if hasattr(resp, "content") else str(resp).upper()

        if verdict_text.startswith("SUPPORTED"):
            supported += 1
        elif verdict_text.startswith("PARTIALLY_SUPPORTED"):
            supported += 0.5
            issues.append(VerificationIssue(
                check="grounding",
                severity="warning",
                message=f"Step {step.step_number}: partially supported — {resp.content.strip()[:200]}",
            ))
        else:
            issues.append(VerificationIssue(
                check="grounding",
                severity="error",
                message=f"Step {step.step_number}: not supported — {resp.content.strip()[:200]}",
            ))

    score = supported / len(output.steps)
    return score, issues


def _check_grounding(
    output: RemediationOutput,
    source_text: str,
    *,
    use_llm_judge: bool = True,
) -> tuple[float, list[VerificationIssue]]:
    """Combined grounding check (heuristic + optional LLM judge)."""
    h_score, h_issues = _heuristic_grounding(output, source_text)

    if not use_llm_judge:
        return h_score, h_issues

    if h_score >= 1.0:
        return h_score, h_issues

    j_score, j_issues = _llm_judge_grounding(output, source_text)
    combined = (h_score + j_score) / 2.0
    return combined, h_issues + j_issues


# ------------------------------------------------------------------
# Check 2: Relevance
# ------------------------------------------------------------------

def _check_relevance(
    output: RemediationOutput,
    technical_summary: str,
    mitre_ids: list[str],
) -> tuple[float, list[VerificationIssue]]:
    """Keyword overlap between finding summary and generated steps."""
    issues: list[VerificationIssue] = []
    if not output.steps:
        return 0.0, [VerificationIssue(
            check="relevance", severity="error", message="No steps generated."
        )]

    summary_tokens = _token_set(technical_summary)
    all_step_text = " ".join(
        f"{s.title} {s.command_or_action} {s.explanation} "
        f"{s.ui_breadcrumb or ''} {s.step_type or ''} {' '.join(s.substeps)}"
        for s in output.steps
    )
    step_tokens = _token_set(all_step_text)

    if summary_tokens:
        overlap = summary_tokens & step_tokens
        keyword_score = len(overlap) / len(summary_tokens)
    else:
        keyword_score = 0.0

    mitre_mentioned = 0
    step_text_upper = all_step_text.upper()
    for mid in mitre_ids:
        if mid.upper() in step_text_upper:
            mitre_mentioned += 1
    mitre_score = mitre_mentioned / len(mitre_ids) if mitre_ids else 1.0

    score = (keyword_score + mitre_score) / 2.0

    if keyword_score < 0.1:
        issues.append(VerificationIssue(
            check="relevance",
            severity="warning",
            message=f"Low keyword overlap ({keyword_score:.2f}) between finding summary and steps.",
        ))
    missing_mitre = [m for m in mitre_ids if m.upper() not in step_text_upper]
    if missing_mitre:
        issues.append(VerificationIssue(
            check="relevance",
            severity="warning",
            message=f"MITRE IDs not referenced in steps: {', '.join(missing_mitre)}",
        ))

    return score, issues


# ------------------------------------------------------------------
# Check 3: Completeness
# ------------------------------------------------------------------

def _check_completeness(
    output: RemediationOutput,
    correlation: dict[str, Any],
    *,
    graph_plus_search: bool = False,
) -> tuple[float, list[VerificationIssue]]:
    """Check that output references top correlated controls."""
    issues: list[VerificationIssue] = []

    top_control_ids: list[str] = []
    best = correlation.get("best_control")
    if best:
        top_control_ids.append(best.get("control_id", ""))

    for bucket in ("vendor_controls", "framework_controls"):
        for cand in correlation.get(bucket, []):
            ctrl = cand.get("control") or {}
            cid = ctrl.get("control_id", "")
            if cid and cid not in top_control_ids:
                top_control_ids.append(cid)
            if len(top_control_ids) >= 3:
                break
        if len(top_control_ids) >= 3:
            break

    if not top_control_ids:
        return 1.0, []

    referenced = list(output.source_control_ids)

    def _prefix_match(top_id: str, ref_ids: list[str]) -> bool:
        """True if any ref ID is a prefix of top_id or vice-versa."""
        for rid in ref_ids:
            if top_id.startswith(rid) or rid.startswith(top_id):
                return True
        return False

    matched = sum(1 for cid in top_control_ids if _prefix_match(cid, referenced))
    score = matched / len(top_control_ids)

    if graph_plus_search:
        if matched >= 1:
            pass
        elif output.limitations:
            score = max(score, config.COMPLETENESS_THRESHOLD)

    missing = [cid for cid in top_control_ids if not _prefix_match(cid, referenced)]
    if missing:
        short_ids = [cid[:60] for cid in missing]
        issues.append(VerificationIssue(
            check="completeness",
            severity="warning",
            message=f"Top controls not referenced in output: {'; '.join(short_ids)}",
        ))

    return score, issues


# ------------------------------------------------------------------
# Check 4: Substep quality
# ------------------------------------------------------------------

_CLI_PREFIXES = re.compile(
    r"^(\$|>|```|Set-|Get-|New-|Remove-|Enable-|Disable-|Add-|netsh\s|reg\s|"
    r"gpupdate|wmic\s|powershell|cmd\s|chmod\s|chown\s|sudo\s|apt\s|yum\s|"
    r"systemctl\s|iptables\s|firewall-cmd)",
    re.IGNORECASE,
)

_CONFIRMATION_KEYWORDS = re.compile(
    r"(verify|confirm|should see|check that|you will see|expected result|appears as|"
    r"shows as|is now set to|is displayed|validates|successful)",
    re.IGNORECASE,
)


def _is_cli_step(command_or_action: str) -> bool:
    """Heuristic: True when the action looks like a CLI command rather than UI navigation."""
    return bool(_CLI_PREFIXES.search(command_or_action.strip()))


def _check_substep_quality(
    output: RemediationOutput,
) -> tuple[float, list[VerificationIssue]]:
    """Validate substep depth, breadcrumb presence, and confirmation hints."""
    issues: list[VerificationIssue] = []
    if not output.steps:
        return 0.0, [VerificationIssue(
            check="substep_quality", severity="error", message="No steps generated."
        )]

    passing = 0

    for step in output.steps:
        step_ok = True

        if len(step.substeps) == 0:
            issues.append(VerificationIssue(
                check="substep_quality",
                severity="error",
                message=f"Step {step.step_number} ('{step.title}') has 0 substeps; minimum is 3.",
            ))
            step_ok = False
        elif len(step.substeps) < 3:
            issues.append(VerificationIssue(
                check="substep_quality",
                severity="warning",
                message=f"Step {step.step_number} ('{step.title}') has only {len(step.substeps)} substep(s); recommended minimum is 3.",
            ))

        if not _is_cli_step(step.command_or_action) and not step.ui_breadcrumb:
            issues.append(VerificationIssue(
                check="substep_quality",
                severity="warning",
                message=f"Step {step.step_number} ('{step.title}') appears to be UI-based but has no ui_breadcrumb.",
            ))

        has_confirm = any(
            _CONFIRMATION_KEYWORDS.search(s) for s in step.substeps
        )
        if step.substeps and not has_confirm:
            issues.append(VerificationIssue(
                check="substep_quality",
                severity="warning",
                message=f"Step {step.step_number} ('{step.title}') has no confirmation/verification substep.",
            ))

        if step_ok:
            passing += 1

    score = passing / len(output.steps)
    return score, issues


# ------------------------------------------------------------------
# Public API: SelfRAGVerifier
# ------------------------------------------------------------------

class SelfRAGVerifier:
    """Four-check verifier for generated remediation."""

    def __init__(self, *, use_llm_judge: bool = True) -> None:
        self.use_llm_judge = use_llm_judge

    def verify(
        self,
        output: RemediationOutput,
        correlation: dict[str, Any],
        technical_summary: str,
        mitre_ids: list[str],
        *,
        graph_plus_search: bool = False,
        grounding_source_blob: str = "",
    ) -> VerificationResult:
        controls_text, _ = _format_controls_text(correlation)
        blob = grounding_source_blob or ""
        prefix = ""
        if graph_plus_search and not blob.strip():
            prefix = (
                "WARNING: Google Search grounding was enabled but no grounding excerpts "
                "were attached. Treat vendor-specific UI details as unsupported unless "
                "they appear in SOURCE CONTROLS.\n\n"
            )
        source_text = prefix + controls_text + (f"\n\n{blob}" if blob.strip() else "")

        g_score, g_issues = _check_grounding(
            output, source_text, use_llm_judge=self.use_llm_judge,
        )
        r_score, r_issues = _check_relevance(output, technical_summary, mitre_ids)
        c_score, c_issues = _check_completeness(
            output, correlation, graph_plus_search=graph_plus_search,
        )
        sq_score, sq_issues = _check_substep_quality(output)

        all_issues = g_issues + r_issues + c_issues + sq_issues
        passed = (
            g_score >= config.GROUNDING_THRESHOLD
            and r_score >= config.RELEVANCE_THRESHOLD
            and c_score >= config.COMPLETENESS_THRESHOLD
            and sq_score >= config.SUBSTEP_QUALITY_THRESHOLD
        )

        return VerificationResult(
            grounding_score=round(g_score, 4),
            relevance_score=round(r_score, 4),
            completeness_score=round(c_score, 4),
            substep_quality_score=round(sq_score, 4),
            passed=passed,
            issues=all_issues,
            attempts=1,
        )


# ------------------------------------------------------------------
# Self-RAG loop: generate -> verify -> retry
# ------------------------------------------------------------------

def generate_with_verification(
    finding: dict[str, Any],
    correlation: dict[str, Any],
    tech_stack: list[str] | None = None,
    *,
    use_llm_judge: bool = True,
    max_retries: int | None = None,
    enable_search_augmentation: bool = False,
) -> tuple[RemediationOutput, VerificationResult, RemediationProvenance]:
    """Generate remediation and run Self-RAG verification loop.

    Returns the best (output, verification, provenance). If all attempts fail
    verification, the last attempt is returned anyway (with ``passed=False``).
    """
    retries = max_retries if max_retries is not None else config.MAX_RETRIES
    verifier = SelfRAGVerifier(use_llm_judge=use_llm_judge)

    meta = finding.get("metadata") or {}
    mitre_ids = (meta.get("mitre_mapping") or {}).get("mitre_ids", [])
    summary = meta.get("technical_summary", "")

    stack = tech_stack or config.GLOBAL_TECH_STACK
    use_search, reason = should_augment_with_search(
        finding,
        correlation,
        stack,
        cli_enable_search=enable_search_augmentation,
    )

    output, provenance = generate_remediation(
        finding,
        correlation,
        stack,
        use_search=use_search,
        search_trigger_reason=reason,
    )
    gps = provenance.mode == "graph_plus_search"
    blob = grounding_metadata_to_source_blob(provenance.grounding_metadata) if gps else ""
    verification = verifier.verify(
        output,
        correlation,
        summary,
        mitre_ids,
        graph_plus_search=gps,
        grounding_source_blob=blob,
    )
    verification.attempts = 1

    attempt = 1
    while not verification.passed and attempt <= retries:
        attempt += 1
        rejection_text = "\n".join(
            f"- [{i.check}/{i.severity}] {i.message}" for i in verification.issues
        )
        output, provenance = generate_remediation(
            finding,
            correlation,
            stack,
            rejection_issues=rejection_text,
            use_search=use_search,
            search_trigger_reason=reason,
        )
        gps = provenance.mode == "graph_plus_search"
        blob = grounding_metadata_to_source_blob(provenance.grounding_metadata) if gps else ""
        verification = verifier.verify(
            output,
            correlation,
            summary,
            mitre_ids,
            graph_plus_search=gps,
            grounding_source_blob=blob,
        )
        verification.attempts = attempt

    return output, verification, provenance
