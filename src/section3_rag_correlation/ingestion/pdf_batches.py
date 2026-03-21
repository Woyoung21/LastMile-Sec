"""Load PDFs with PyMuPDFLoader and group pages into fixed-size batches."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from langchain_core.documents import Document
from langchain_community.document_loaders import PyMuPDFLoader

from src.section3_rag_correlation import config


@dataclass(frozen=True)
class PageBatch:
    """A consecutive run of pages from one PDF."""

    pdf_path: Path
    batch_index: int  # 0-based index among batches for this file
    start_page: int  # 0-based inclusive
    end_page: int  # 0-based inclusive
    documents: list[Document]

    def text(self) -> str:
        parts = []
        for d in self.documents:
            p = (d.metadata.get("page") or d.metadata.get("page_number") or 0)
            parts.append(f"--- Page {int(p) + 1} ---\n{d.page_content}")
        return "\n\n".join(parts)


def load_page_documents(pdf_path: Path) -> list[Document]:
    """Load one PDF; each element is typically one page."""
    loader = PyMuPDFLoader(str(pdf_path))
    return loader.load()


def iter_page_batches(pdf_path: Path) -> list[PageBatch]:
    """Split all pages into batches of PAGE_BATCH_SIZE (default 5)."""
    docs = load_page_documents(pdf_path)
    batches: list[PageBatch] = []
    size = config.PAGE_BATCH_SIZE
    for bi, i in enumerate(range(0, len(docs), size)):
        chunk = docs[i : i + size]
        pages = []
        for d in chunk:
            p = d.metadata.get("page")
            if p is None:
                p = d.metadata.get("page_number", 0)
            pages.append(int(p))
        start_page = min(pages) if pages else i
        end_page = max(pages) if pages else i + len(chunk) - 1
        batches.append(
            PageBatch(
                pdf_path=pdf_path.resolve(),
                batch_index=bi,
                start_page=start_page,
                end_page=end_page,
                documents=chunk,
            )
        )
    return batches


def list_corpus_pdfs(corpus_dir: Path) -> list[Path]:
    """Return sorted PDF paths under corpus_dir."""
    if not corpus_dir.is_dir():
        return []
    return sorted(p for p in corpus_dir.rglob("*.pdf") if p.is_file())
