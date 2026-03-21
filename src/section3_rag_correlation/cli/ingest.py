"""Ingest RAG_Corpus PDFs: batch extract → embed remediation → MERGE into Neo4j."""

from __future__ import annotations

import argparse
import traceback
from pathlib import Path

from src.section3_rag_correlation import config
from src.section3_rag_correlation.graph.merge_controls import merge_security_control
from src.section3_rag_correlation.graph.neo4j_client import apply_schema, get_driver
from src.section3_rag_correlation.ingestion.extract import extract_batch
from src.section3_rag_correlation.ingestion.pdf_batches import iter_page_batches, list_corpus_pdfs
from src.section3_rag_correlation.ingestion.progress import (
    ProgressEntry,
    append_progress,
    load_completed_batch_indices,
)
from src.section3_rag_correlation.llm import get_embeddings


def run_ingest(
    corpus_dir: Path | None = None,
    apply_graph_schema: bool = True,
    limit_pdfs: int | None = None,
    limit_batches: int | None = None,
) -> None:
    corpus = corpus_dir or config.RAG_CORPUS_DIR
    config.ensure_log_dir()
    log_path = config.PROCESSED_PAGES_LOG

    pdfs = list_corpus_pdfs(corpus)
    if limit_pdfs is not None:
        pdfs = pdfs[:limit_pdfs]
    if not pdfs:
        print(f"No PDF files under {corpus}")
        return

    driver = get_driver()
    if apply_graph_schema:
        print("Applying Neo4j schema (constraints + vector index)...")
        apply_schema(driver)

    embedder = get_embeddings()

    batches_done = 0
    try:
        for pdf in pdfs:
            done_idx = load_completed_batch_indices(log_path, pdf)
            batches = iter_page_batches(pdf)
            for batch in batches:
                if batch.batch_index in done_idx:
                    print(f"Skip completed batch {batch.batch_index} {pdf.name}")
                    continue
                if limit_batches is not None and batches_done >= limit_batches:
                    print(
                        f"Stopped after {limit_batches} batch(es) (--limit-batches). "
                        "Run without --limit-batches for a full ingest."
                    )
                    print("Ingest finished.")
                    return

                text = batch.text()
                print(
                    f"Extracting {pdf.name} batch {batch.batch_index} "
                    f"(pages {batch.start_page}-{batch.end_page})..."
                )
                try:
                    controls = extract_batch(text)
                except Exception as e:
                    append_progress(
                        log_path,
                        ProgressEntry(
                            pdf_path=str(batch.pdf_path),
                            batch_index=batch.batch_index,
                            start_page=batch.start_page,
                            end_page=batch.end_page,
                            status="error",
                            detail=str(e),
                        ),
                    )
                    print(f"  extraction error: {e}")
                    continue

                for ctrl in controls:
                    try:
                        # Index as retrieval documents (pairs with RETRIEVAL_QUERY in correlate).
                        emb = embedder.embed_documents([ctrl.remediation_steps])[0]
                        if len(emb) != config.EMBEDDING_DIMENSIONS:
                            raise ValueError(
                                f"embedding dim {len(emb)} != {config.EMBEDDING_DIMENSIONS}"
                            )
                        merge_security_control(driver, ctrl, emb)
                        print(f"  merged control {ctrl.control_id!r}")
                    except Exception as e:
                        print(f"  merge error for {ctrl.control_id!r}: {e}")
                        traceback.print_exc()

                append_progress(
                    log_path,
                    ProgressEntry(
                        pdf_path=str(batch.pdf_path),
                        batch_index=batch.batch_index,
                        start_page=batch.start_page,
                        end_page=batch.end_page,
                        status="ok",
                        detail=None,
                    ),
                )
                batches_done += 1
    finally:
        driver.close()

    print("Ingest finished.")


def main() -> None:
    p = argparse.ArgumentParser(description="Section 3 PDF → Neo4j ingest")
    p.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help="Directory containing PDFs (default: RAG_CORPUS_DIR from env)",
    )
    p.add_argument(
        "--no-schema",
        action="store_true",
        help="Do not run schema.cypher (constraints + vector index)",
    )
    p.add_argument("--limit-pdfs", type=int, default=None)
    p.add_argument("--limit-batches", type=int, default=None)
    args = p.parse_args()
    run_ingest(
        corpus_dir=args.corpus,
        apply_graph_schema=not args.no_schema,
        limit_pdfs=args.limit_pdfs,
        limit_batches=args.limit_batches,
    )


if __name__ == "__main__":
    main()
