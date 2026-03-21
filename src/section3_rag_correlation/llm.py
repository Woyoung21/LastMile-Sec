"""Gemini chat (LangChain) + embeddings (google.genai Client, gemini-embedding-001 @ 768d)."""

from __future__ import annotations

from langchain_google_genai import ChatGoogleGenerativeAI

from src.section3_rag_correlation import config
from src.section3_rag_correlation.embeddings_gemini import GeminiEmbedding768

# Global cache: avoids repeated SSL / client construction per PDF batch.
_CHAT_LLM: ChatGoogleGenerativeAI | None = None
_EMBEDDINGS: GeminiEmbedding768 | None = None


def get_chat_llm() -> ChatGoogleGenerativeAI:
    global _CHAT_LLM
    if _CHAT_LLM is None:
        if not config.GOOGLE_API_KEY:
            raise RuntimeError("GOOGLE_API_KEY is not set (see .env.example).")
        _CHAT_LLM = ChatGoogleGenerativeAI(
            model=config.GEMINI_MODEL,
            google_api_key=config.GOOGLE_API_KEY,
            temperature=0.1,
        )
    return _CHAT_LLM


def get_embeddings() -> GeminiEmbedding768:
    global _EMBEDDINGS
    if _EMBEDDINGS is None:
        _EMBEDDINGS = GeminiEmbedding768()
    return _EMBEDDINGS


def assert_embedding_dim(vector: list[float]) -> None:
    if len(vector) != config.EMBEDDING_DIMENSIONS:
        raise ValueError(
            f"Expected embedding length {config.EMBEDDING_DIMENSIONS}, got {len(vector)}"
        )
