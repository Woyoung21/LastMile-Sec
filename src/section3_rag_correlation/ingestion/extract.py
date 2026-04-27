"""Structured Gemini extraction for each page batch."""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

from src.common.gemini_transient import invoke_with_transient_retry
from src.section3_rag_correlation.llm import get_chat_llm
from src.section3_rag_correlation.schemas import ExtractionBatch, SecurityControl


EXTRACTION_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You extract security hardening controls from standards documents (NIST, CIS, STIG, vendor guides). "
            "Return structured data only. If a batch has no clear controls, return an empty controls list. "
            "MITRE IDs must be ATT&CK technique IDs like T1190 or T1059.004 when explicitly implied.",
        ),
        (
            "human",
            "From the following PDF excerpt, extract zero or more distinct SecurityControl records.\n\n{text}",
        ),
    ]
)


def extract_batch(page_text: str) -> list[SecurityControl]:
    """Run Gemini structured extraction on one batch of pages."""
    llm = get_chat_llm()
    structured = llm.with_structured_output(ExtractionBatch)
    chain = EXTRACTION_PROMPT | structured
    result: ExtractionBatch = invoke_with_transient_retry(
        lambda: chain.invoke({"text": page_text})
    )
    return list(result.controls)
