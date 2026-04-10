"""Prompt templates for remediation generation and Self-RAG verification."""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

# Shared L1/L2 style rules (prepended to system prompts).
_L1_L2_BLOCK = (
    "L1/L2 WALKTHROUGH STYLE — MANDATORY RULES:\n"
    "- Start with executive_summary (2–4 sentences) unless the finding is trivial.\n"
    "- Number steps clearly. For CLI or PowerShell, put exact commands in command_or_action.\n"
    "- Classify each step with step_type: 'investigation' for log review and triage, "
    "'hardening' for configuration changes that reduce attack surface, "
    "'monitoring' for setting up ongoing detection or alerting.\n"
    "- SUBSTEP REQUIREMENTS (strictly enforced):\n"
    "  * Every step MUST have at least 3 substeps. Never return an empty substeps list.\n"
    "  * If a step is investigative (reviewing logs, checking status), still provide at least "
    "3 substeps describing exactly where to look and what to look for.\n"
    "  * The final substep of each step SHOULD describe what the engineer will see on screen "
    "to confirm the action succeeded (e.g., 'You should see the policy now shows Disabled').\n"
    "- UI BREADCRUMB REQUIREMENTS (strictly enforced):\n"
    "  * Every step that navigates a GUI, web console, or management interface MUST have a "
    "non-null ui_breadcrumb using ' > ' separators "
    "(example: Meraki dashboard > Security > L3 firewall rules).\n"
    "  * For UI work, fill substeps with ordered click-by-click micro-steps; quote the on-screen "
    "labels exactly where possible.\n"
    "- Set evidence_tier on each step: 'graph' when sourced from SOURCE CONTROLS below; "
    "'vendor_doc' for official vendor docs; 'search_secondary' for forums or non-official pages.\n"
    "- For graph-only runs, use evidence_tier 'graph' for all steps.\n"
)

# ---------------------------------------------------------------------------
# Remediation generation (graph only — Neo4j controls)
# ---------------------------------------------------------------------------

REMEDIATION_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a senior security engineer writing step-by-step remediation "
            "instructions for L1/L2 operations staff.\n\n"
            + _L1_L2_BLOCK
            + "\nRULES:\n"
            "1. Base every command, registry path, and configuration change on the "
            "   SOURCE CONTROLS provided below. Do NOT invent commands, paths, or "
            "   settings that are not present in or directly derivable from the source text.\n"
            "2. Scope instructions to the CLIENT TECH STACK. Omit steps that target "
            "   products not in the stack.\n"
            "3. Each step must be concrete and copy-pasteable where possible when the source is CLI-oriented.\n"
            "4. Include a verification procedure the engineer can run to confirm the fix.\n"
            "5. Reference the source control IDs so the engineer can trace guidance back "
            "   to the authoritative standard.\n"
            "6. Set priority based on the finding severity and MITRE tactic.\n"
            "7. Estimate effort realistically for an L1/L2 engineer.\n"
            "8. Leave limitations empty unless there is a material caveat in the source controls.",
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
# Remediation + Google Search grounding (Gemini tool)
# ---------------------------------------------------------------------------

REMEDIATION_PROMPT_WITH_SEARCH = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a senior security engineer writing step-by-step remediation "
            "instructions for L1/L2 operations staff.\n\n"
            + _L1_L2_BLOCK
            + "\nGOOGLE SEARCH GROUNDING:\n"
            "- You have access to Google Search. Use it to fill vendor-specific UI gaps when "
            "SOURCE CONTROLS are generic (e.g. NIST/CIS) or not specific to the product console.\n"
            "- Prefer official vendor documentation and vendor knowledge bases over forums.\n"
            "- Every menu path and UI label must be copied or clearly paraphrased from retrieved text. "
            "Do not invent Meraki/Ubiquiti/UniFi navigation that search did not support.\n"
            "- Put authoritative URLs the user should open in supporting_urls on the relevant steps.\n"
            "- If only community or secondary pages were found, set evidence_tier to 'search_secondary' "
            "and explain in limitations.\n"
            "- If search results are weak, contradictory, or version-dependent, document that in limitations.\n"
            "\nBASE RULES:\n"
            "1. Still align remediation with SOURCE CONTROLS where they apply; use search for product-specific UI.\n"
            "2. Scope instructions to the CLIENT TECH STACK.\n"
            "3. Include verification the L1/L2 engineer can perform.\n"
            "4. Reference source control IDs from the graph in source_control_ids whenever those controls informed a step.\n"
            "5. Set priority from severity and MITRE context.\n",
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
            "SOURCE CONTROLS (from graph / standards corpus)\n"
            "----------------------------------------------\n"
            "{controls_text}\n\n"
            "Use search grounding as needed for vendor-specific UI walkthroughs. "
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
            "You are a factuality auditor. Given SOURCE TEXT (controls plus optional search excerpts) "
            "and a GENERATED REMEDIATION STEP (including its UI breadcrumb and substeps), "
            "determine whether the step is factually supported.\n\n"
            "Pay special attention to UI breadcrumbs and substeps — menu paths and on-screen labels "
            "must be derivable from the source text. Invented navigation paths count as NOT_SUPPORTED.\n\n"
            "Reply with exactly one of:\n"
            "  SUPPORTED — the step is directly stated in or clearly derivable from the source.\n"
            "  PARTIALLY_SUPPORTED — the step is loosely related but adds specifics not in the source.\n"
            "  NOT_SUPPORTED — the step introduces commands, paths, or claims absent from the source.\n\n"
            "After your verdict, provide a one-sentence rationale.",
        ),
        (
            "human",
            "SOURCE TEXT:\n{source_text}\n\n"
            "GENERATED STEP:\n"
            "Title: {step_title}\n"
            "Action: {step_action}\n"
            "UI Breadcrumb: {step_breadcrumb}\n"
            "Substeps:\n{step_substeps}\n"
            "Explanation: {step_explanation}\n\n"
            "Verdict:",
        ),
    ]
)

# ---------------------------------------------------------------------------
# Retry prompts
# ---------------------------------------------------------------------------

RETRY_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a senior security engineer writing step-by-step remediation "
            "instructions for L1/L2 operations staff.\n\n"
            + _L1_L2_BLOCK
            + "\nYour PREVIOUS attempt was rejected by the verification layer. "
            "The issues are listed below. Correct them while still following "
            "the grounding rules:\n"
            "1. Base every command, registry path, and configuration change on the "
            "   SOURCE CONTROLS provided below.\n"
            "2. Scope instructions to the CLIENT TECH STACK.\n"
            "3. Each step must be concrete and copy-pasteable where possible.\n"
            "4. Address ALL rejection issues listed below.\n"
            "5. Pay special attention: every step MUST have >= 3 substeps and "
            "UI-oriented steps MUST have a non-null ui_breadcrumb.",
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

RETRY_PROMPT_WITH_SEARCH = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a senior security engineer writing step-by-step remediation "
            "for L1/L2 operations staff.\n\n"
            + _L1_L2_BLOCK
            + "\nGOOGLE SEARCH GROUNDING is enabled. Use it per the constraints in the initial search prompt: "
            "prefer vendor docs, cite URLs in supporting_urls, label secondary sources, and use limitations honestly.\n\n"
            "Your PREVIOUS attempt was rejected. Fix ALL issues below while respecting grounding.\n"
            "Pay special attention: every step MUST have >= 3 substeps and "
            "UI-oriented steps MUST have a non-null ui_breadcrumb.",
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
            "SOURCE CONTROLS\n"
            "----------------------------------------------\n"
            "{controls_text}\n\n"
            "REJECTION ISSUES FROM PREVIOUS ATTEMPT\n"
            "---------------------------------------\n"
            "{rejection_issues}\n\n"
            "Produce corrected structured remediation output.",
        ),
    ]
)
