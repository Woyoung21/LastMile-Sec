"""Grounding metadata serialization for Self-RAG."""

from __future__ import annotations

from src.section4_remediation.grounding_serialization import (
    grounding_metadata_to_source_blob,
    json_safe_grounding_metadata,
)


def test_grounding_blob_from_chunks() -> None:
    meta = {
        "web_search_queries": ["Meraki disable ssh"],
        "grounding_chunks": [
            {
                "web": {
                    "uri": "https://documentation.meraki.com/example",
                    "title": "Meraki doc",
                },
            },
        ],
    }
    blob = grounding_metadata_to_source_blob(meta)
    assert "Meraki doc" in blob
    assert "documentation.meraki.com" in blob
    assert "Meraki disable ssh" in blob


def test_json_safe_handles_nested() -> None:
    meta = {"groundingChunks": [], "webSearchQueries": []}
    safe = json_safe_grounding_metadata(meta)
    assert isinstance(safe, dict)
