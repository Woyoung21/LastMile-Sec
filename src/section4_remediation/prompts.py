"""Prompt templates for remediation generation and Self-RAG verification."""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

# ---------------------------------------------------------------------------
# Remediation generation (grounded in retrieved controls)
# ---------------------------------------------------------------------------

REMEDIATION_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a senior security engineer writing step-by-step remediation "
            "instructions for L1/L2 operations staff.\n\n"
            "RULES:\n"
            "1. Base every command, registry path, and configuration change on the "
            "   SOURCE CONTROLS provided below. Do NOT invent commands, paths, or "
            "   settings that are not present in or directly derivable from the source text.\n"
            "2. Scope instructions to the CLIENT TECH STACK. Omit steps that target "
            "   products not in the stack.\n"
            "3. Each step must be concrete and copy-pasteable where possible.\n"
            "4. Include a verification procedure the engineer can run to confirm the fix.\n"
            "5. Reference the source control IDs so the engineer can trace guidance back "
            "   to the authoritative standard.\n"
            "6. Set priority based on the finding severity and MITRE tactic.\n"
            "7. Estimate effort realistically for an L1/L2 engineer.",
        ),
        (
            "human",
            "FINDING\n"
            "-------\n"
            "Summary: {technical_summary}\n"
            "Severity: {severity}\n"
            "MITRE ATT&CK IDs: {mitre_ids}\n\n"
            "CLIENT TECH STACK\n"
            "-----------------\n"
            "{tech_stack}\n\n"
            "SOURCE CONTROLS (from authoritative standards)\n"
            "----------------------------------------------\n"
            "{controls_text}\n\n"
            "Produce structured remediation output.",
        ),
    ]
)

# ---------------------------------------------------------------------------
# Self-RAG: grounding check (LLM-as-judge)
# ---------------------------------------------------------------------------

GROUNDING_CHECK_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a factuality auditor. Given SOURCE CONTROL TEXT and a "
            "GENERATED REMEDIATION STEP, determine whether the step is factually "
            "supported by the source.\n\n"
            "Reply with exactly one of:\n"
            "  SUPPORTED — the step is directly stated in or clearly derivable from the source.\n"
            "  PARTIALLY_SUPPORTED — the step is loosely related but adds specifics not in the source.\n"
            "  NOT_SUPPORTED — the step introduces commands, paths, or claims absent from the source.\n\n"
            "After your verdict, provide a one-sentence rationale.",
        ),
        (
            "human",
            "SOURCE CONTROL TEXT:\n{source_text}\n\n"
            "GENERATED STEP:\n"
            "Title: {step_title}\n"
            "Action: {step_action}\n"
            "Explanation: {step_explanation}\n\n"
            "Verdict:",
        ),
    ]
)

# ---------------------------------------------------------------------------
# Retry prompt (augmented with rejection reasons)
# ---------------------------------------------------------------------------

RETRY_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a senior security engineer writing step-by-step remediation "
            "instructions for L1/L2 operations staff.\n\n"
            "Your PREVIOUS attempt was rejected by the verification layer. "
            "The issues are listed below. Correct them while still following "
            "the grounding rules:\n"
            "1. Base every command, registry path, and configuration change on the "
            "   SOURCE CONTROLS provided below.\n"
            "2. Scope instructions to the CLIENT TECH STACK.\n"
            "3. Each step must be concrete and copy-pasteable where possible.\n"
            "4. Address ALL rejection issues listed below.",
        ),
        (
            "human",
            "FINDING\n"
            "-------\n"
            "Summary: {technical_summary}\n"
            "Severity: {severity}\n"
            "MITRE ATT&CK IDs: {mitre_ids}\n\n"
            "CLIENT TECH STACK\n"
            "-----------------\n"
            "{tech_stack}\n\n"
            "SOURCE CONTROLS (from authoritative standards)\n"
            "----------------------------------------------\n"
            "{controls_text}\n\n"
            "REJECTION ISSUES FROM PREVIOUS ATTEMPT\n"
            "---------------------------------------\n"
            "{rejection_issues}\n\n"
            "Produce corrected structured remediation output.",
        ),
    ]
)
