"""Pydantic models for Gemini structured extraction and graph payloads."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class SecurityControl(BaseModel):
    """Target structure for corpus extraction (per tasks.txt)."""

    control_id: str = Field(
        description="Unique ID, e.g., CIS 1.1.1 or NIST AC-2",
    )
    vendor_product: str = Field(
        description="The OS, hardware, or app, e.g., 'Meraki MS' or 'Windows Server'",
    )
    remediation_steps: str = Field(
        description="The exact technical commands or steps to fix the issue",
    )
    mitre_mapping: Optional[list[str]] = Field(
        default=None,
        description="Associated MITRE ATT&CK Technique IDs",
    )
    audit_procedure: Optional[str] = Field(
        default=None,
        description="How to verify the fix is applied",
    )


class ExtractionBatch(BaseModel):
    """Wrapper for structured LLM output (may be empty for a page batch)."""

    controls: list[SecurityControl] = Field(
        default_factory=list,
        description="Security controls extracted from the supplied page text",
    )
