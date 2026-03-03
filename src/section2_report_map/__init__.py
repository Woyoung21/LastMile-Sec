"""
Section 2: Report & Mapper

This section takes the normalized JSON packets from Section 1 (Ingestion)
and enriches them with:
1. Technical summary sentences (via Gemini Reporter)
2. MITRE ATT&CK technique mappings (via Mistral-7B LoRA + Actian VectorAI RAG)
"""

__version__ = "1.0.0"

from .mapper import (
    ActianVectorAIDBClient,
    FindingReport,
    Mapper,
    MitreMappingResult,
    MitreValidator,
)
from .reporter import Reporter

__all__ = [
    "ActianVectorAIDBClient",
    "FindingReport",
    "Mapper",
    "MitreMappingResult",
    "MitreValidator",
    "Reporter",
]
