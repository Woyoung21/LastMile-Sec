"""Serialize Gemini grounding_metadata for JSON output and Self-RAG source text."""

from __future__ import annotations

import json
from typing import Any


def _chunk_to_lines(chunk: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    web = chunk.get("web") if isinstance(chunk.get("web"), dict) else None
    if web:
        uri = web.get("uri") or web.get("url")
        title = web.get("title")
        if title:
            lines.append(f"  Title: {title}")
        if uri:
            lines.append(f"  URL: {uri}")
    retrieved = chunk.get("retrieved_context")
    if isinstance(retrieved, dict):
        t = retrieved.get("text") or retrieved.get("uri")
        if t:
            lines.append(f"  Context: {t}")
    return lines


def _normalize_grounding_meta(meta: dict[str, Any]) -> dict[str, Any]:
    """Merge camelCase API keys with snake_case from LangChain."""
    out = dict(meta)
    if "grounding_chunks" not in out and "groundingChunks" in out:
        out["grounding_chunks"] = out.get("groundingChunks")
    if "grounding_supports" not in out and "groundingSupports" in out:
        out["grounding_supports"] = out.get("groundingSupports")
    if "web_search_queries" not in out and "webSearchQueries" in out:
        out["web_search_queries"] = out.get("webSearchQueries")
    return out


def grounding_metadata_to_source_blob(meta: dict[str, Any] | None) -> str:
    """Human-readable excerpt for Self-RAG grounding checks."""
    if not meta:
        return ""

    meta = _normalize_grounding_meta(meta)
    parts: list[str] = ["--- GOOGLE SEARCH GROUNDING (excerpts) ---"]

    queries = meta.get("web_search_queries") or []
    if queries:
        parts.append("Queries: " + "; ".join(str(q) for q in queries))

    chunks = meta.get("grounding_chunks") or []
    for i, ch in enumerate(chunks, start=1):
        if not isinstance(ch, dict):
            continue
        sub = _chunk_to_lines(ch)
        if sub:
            parts.append(f"[Chunk {i}]")
            parts.extend(sub)

    supports = meta.get("grounding_supports") or []
    for i, sup in enumerate(supports[:20], start=1):
        if not isinstance(sup, dict):
            continue
        seg = sup.get("segment", {})
        text = ""
        if isinstance(seg, dict):
            text = seg.get("text") or ""
        if text:
            parts.append(f"[Support {i}] {text[:500]}")

    return "\n".join(parts) if len(parts) > 1 else ""


def json_safe_grounding_metadata(meta: Any) -> dict[str, Any] | None:
    """Return a JSON-serializable dict or None."""
    if meta is None:
        return None
    if not isinstance(meta, dict):
        return {"_raw": str(meta)}
    try:
        return json.loads(json.dumps(_normalize_grounding_meta(meta), default=str))
    except (TypeError, ValueError):
        return {"_raw": str(meta)}
