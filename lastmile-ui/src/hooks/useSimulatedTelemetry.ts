"use client";

import { useEffect, useState } from "react";

export type LogLevel = "info" | "warn" | "debug";

/** Banner rows mirror run_pipeline.py section headers (no [level] prefix in UI). */
export type TelemetryLine =
  | { kind: "banner"; text: string }
  | { kind: "log"; t: string; level: LogLevel; text: string };

export const BANNER_LINE = "============================================================";

function ts(): string {
  return new Date().toISOString().split("T")[1].slice(0, 12);
}

/**
 * Deterministic scripted sequence aligned with `run_pipeline.py` orchestration.
 * Swap for SSE later without changing the terminal shell.
 */
function buildPipelineScript(): TelemetryLine[] {
  const lines: TelemetryLine[] = [];

  const addBanner = (s: string) => lines.push({ kind: "banner", text: s });
  const log = (level: LogLevel, text: string) =>
    lines.push({ kind: "log", t: ts(), level, text });

  addBanner(BANNER_LINE);
  addBanner("  Pipeline: Section 1 (run.py, langextract)");
  addBanner(BANNER_LINE);
  log("info", "LangExtract PDF surface index ready; tokenizer attached");
  log("debug", "chunking heuristic: narrative vs table spans");
  log("info", "emitting findings[] to normalized schema v2");
  log(
    "info",
    "Saved to: data/processed/ingest_example_20260417_processed.json",
  );

  addBanner(BANNER_LINE);
  addBanner("  Pipeline: Section 2 (run_section2.py)");
  addBanner(BANNER_LINE);
  log("info", "mapper routing-mode=local; embedding batch warm");
  log("debug", "vector query Actian-VectorAI: top_k examples retrieved");
  log("info", "MITRE id post-process → metadata.mitre_mapping.mitre_ids");
  log(
    "info",
    "Pipeline complete. Output: data/mapped/ingest_example_20260417_mapped.json",
  );

  addBanner(BANNER_LINE);
  addBanner("  Pipeline: Section 3 (correlate)");
  addBanner(BANNER_LINE);
  log("info", "Neo4j correlation: vendor controls fused with MITRE edges");
  log("debug", "composite_score tuned; graph path depth=3");
  log("info", "correlate wrote: data/correlate/ingest_example_correlated.json");

  addBanner(BANNER_LINE);
  addBanner("  Pipeline: Section 4 (remediate)");
  addBanner(BANNER_LINE);
  log("info", "remediate CLI: LLM-as-judge enabled");
  log("warn", "selfrag_verification: completeness check advisory on Step 3");
  log("debug", "runbook substeps materialized; executive_summary sealed");
  log(
    "info",
    "remediate output: data/remediated/ingest_example_remediated.json",
  );

  addBanner(BANNER_LINE);
  addBanner("  Pipeline finished successfully.");
  addBanner(BANNER_LINE);

  return lines;
}

/** Pause before the first line after a Section N header triple (run_pipeline banners). */
function needsSectionPauseBeforeIndex(script: TelemetryLine[], i: number): boolean {
  if (i < 3) return false;
  const open = script[i - 3];
  const title = script[i - 2];
  const close = script[i - 1];
  return (
    open?.kind === "banner" &&
    open.text === BANNER_LINE &&
    title?.kind === "banner" &&
    title.text.includes("Pipeline: Section") &&
    close?.kind === "banner" &&
    close.text === BANNER_LINE
  );
}

const SECTION_PAUSE_MS = 1750;
const LINE_GAP_MS = 300;

function delay(ms: number) {
  return new Promise<void>((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

/** Async paced orchestrator log — section headers pause 1.5–2s before body lines. */
export function useSimulatedTelemetry(active: boolean, resetKey?: string) {
  const [lines, setLines] = useState<TelemetryLine[]>([]);

  useEffect(() => {
    if (!active) {
      setLines([]);
      return;
    }

    const script = buildPipelineScript();
    setLines([]);
    let cancelled = false;

    void (async () => {
      for (let i = 0; i < script.length; i++) {
        if (cancelled) return;
        if (i > 0) {
          if (needsSectionPauseBeforeIndex(script, i)) {
            await delay(SECTION_PAUSE_MS);
          } else {
            await delay(LINE_GAP_MS);
          }
        }
        if (cancelled) return;
        const row = script[i];
        setLines((prev) => [...prev, row].slice(-400));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [active, resetKey]);

  return lines;
}
