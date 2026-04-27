"""
768-d embeddings via google.genai Client + gemini-embedding-001.

LangChain's GoogleGenerativeAIEmbeddings targets the same SDK but pairs poorly with
``models/text-embedding-004`` on the v1beta ``embedContent`` route (404). The
supported model for ``embedContent`` is ``gemini-embedding-001`` with
``output_dimensionality=768`` (see Gemini API embeddings docs).
"""

from __future__ import annotations

from google import genai
from google.genai import types
from langchain_core.embeddings import Embeddings

from src.common.gemini_transient import invoke_with_transient_retry
from src.section3_rag_correlation import config


class GeminiEmbedding768(Embeddings):
    """RETRIEVAL_DOCUMENT for indexed text; RETRIEVAL_QUERY for search queries."""

    _MODEL = "gemini-embedding-001"

    def __init__(self) -> None:
        if not config.GOOGLE_API_KEY:
            raise RuntimeError("GOOGLE_API_KEY is not set (see .env.example).")
        self._client = genai.Client(api_key=config.GOOGLE_API_KEY)
        self._dim = config.EMBEDDING_DIMENSIONS

    def embed_query(self, text: str) -> list[float]:
        def _call() -> list[float]:
            result = self._client.models.embed_content(
                model=self._MODEL,
                contents=text,
                config=types.EmbedContentConfig(
                    task_type="RETRIEVAL_QUERY",
                    output_dimensionality=self._dim,
                ),
            )
            return list(result.embeddings[0].values)

        # No model swap: must keep gemini-embedding-001 for a consistent vector space.
        return invoke_with_transient_retry(_call, allow_fallback=False)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        def _call() -> list[list[float]]:
            result = self._client.models.embed_content(
                model=self._MODEL,
                contents=texts,
                config=types.EmbedContentConfig(
                    task_type="RETRIEVAL_DOCUMENT",
                    output_dimensionality=self._dim,
                ),
            )
            return [list(e.values) for e in result.embeddings]

        return invoke_with_transient_retry(_call, allow_fallback=False)
