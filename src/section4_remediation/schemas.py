"""Pydantic models for Section 4 remediation output and Self-RAG verification."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

EvidenceTier = Literal["graph", "vendor_doc", "search_secondary"]
StepType = Literal["investigation", "hardening", "monitoring"]


class RemediationStep(BaseModel):
    """A single actionable step for an L1/L2 engineer."""

    step_number: int = Field(description="Ordinal position (1-based)")
    title: str = Field(description="Short imperative title, e.g. 'Disable anonymous access'")
    command_or_action: str = Field(
        description="Exact command, registry path, UI navigation, or manual action"
    )
    explanation: str = Field(
        description="Why this step matters and what it mitigates"
    )
    vendor_product: Optional[str] = Field(
        default=None,
        description="Target platform this step applies to, e.g. 'Windows Server'",
    )
    step_type: Optional[StepType] = Field(
        default=None,
        description=(
            "investigation=triage/log-review; "
            "hardening=config change to reduce attack surface; "
            "monitoring=set up ongoing detection"
        ),
    )
    ui_breadcrumb: Optional[str] = Field(
        default=None,
        description="UI path using ' > ', e.g. 'Meraki dashboard > Security > L3 firewall'",
    )
    substeps: list[str] = Field(
        default_factory=list,
        description="Ordered click-by-click sub-steps for L1/L2 (quote UI labels where helpful)",
    )
    evidence_tier: Optional[EvidenceTier] = Field(
        default=None,
        description="graph=Neo4j controls; vendor_doc=official docs via search; search_secondary=forums/secondary",
    )
    supporting_urls: list[str] = Field(
        default_factory=list,
        description="URLs from Google Search grounding or explicit citations for this step",
    )


class RemediationOutput(BaseModel):
    """Structured remediation produced by the generator for one finding."""

    steps: list[RemediationStep] = Field(
        description="Ordered remediation steps"
    )
    priority: str = Field(
        description="critical / high / medium / low"
    )
    estimated_effort: str = Field(
        description="Time estimate, e.g. '15 minutes', '1 hour'"
    )
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Access or tools the engineer needs before starting",
    )
    verification: str = Field(
        description="How to confirm the remediation was applied correctly"
    )
    source_control_ids: list[str] = Field(
        default_factory=list,
        description="Control IDs from the graph that informed these steps",
    )
    executive_summary: Optional[str] = Field(
        default=None,
        description="2–4 sentences orienting an L1/L2 engineer before the steps",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Caveats, e.g. weak search results or version-specific UI",
    )


class RemediationProvenance(BaseModel):
    """How remediation was produced (graph vs search-augmented)."""

    mode: Literal["graph_only", "graph_plus_search"] = Field(
        description="graph_only uses Neo4j controls only; graph_plus_search enables Google Search grounding",
    )
    search_trigger_reason: Optional[str] = Field(
        default=None,
        description="Why search augmentation was selected, if applicable",
    )
    grounding_metadata: Optional[dict[str, Any]] = Field(
        default=None,
        description="Raw-ish grounding payload from Gemini (JSON-serializable); optional",
    )


class VerificationIssue(BaseModel):
    """A single issue found by the Self-RAG verifier."""

    check: str = Field(description="grounding | relevance | completeness | substep_quality")
    severity: str = Field(description="error | warning")
    message: str


class VerificationResult(BaseModel):
    """Aggregate Self-RAG verification outcome."""

    grounding_score: float = Field(
        default=0.0, description="0.0-1.0 fraction of steps grounded in source"
    )
    relevance_score: float = Field(
        default=0.0, description="0.0-1.0 keyword overlap between steps and finding"
    )
    completeness_score: float = Field(
        default=0.0, description="0.0-1.0 fraction of top controls referenced"
    )
    substep_quality_score: float = Field(
        default=0.0,
        description="0.0-1.0 fraction of steps meeting substep quality requirements",
    )
    passed: bool = Field(default=False)
    issues: list[VerificationIssue] = Field(default_factory=list)
    attempts: int = Field(default=1, description="How many generation attempts were needed")
