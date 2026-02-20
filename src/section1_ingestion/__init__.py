"""
Section 1: Data Ingestion Pipeline

Handles parsing of raw security data (PDFs, Excel, CSV, PCAP)
and normalizes it into structured JSON packets for downstream processing.

PDF Parser Options:
- "regex": Fast, offline, pattern-based (default)
- "langextract": LLM-powered via Gemini, more accurate
- "auto": Uses LangExtract if GOOGLE_API_KEY is set

Example:
    >>> from src.section1_ingestion import ingest_file, Normalizer
    >>> 
    >>> # Quick usage (regex parser)
    >>> packet = ingest_file("report.pdf")
    >>> 
    >>> # With LangExtract
    >>> normalizer = Normalizer(pdf_parser="langextract")
    >>> packet = normalizer.ingest("report.pdf")
"""

from dotenv import load_dotenv

load_dotenv()

from .schemas import (
    Finding,
    IngestedPacket,
    SourceType,
    Severity,
    AffectedAsset,
    ParserMetadata,
)
from .normalizer import Normalizer, ingest_file, ingest_to_json

__all__ = [
    # Schemas
    "Finding",
    "IngestedPacket",
    "SourceType",
    "Severity",
    "AffectedAsset",
    "ParserMetadata",
    # Normalizer
    "Normalizer",
    "ingest_file",
    "ingest_to_json",
]
