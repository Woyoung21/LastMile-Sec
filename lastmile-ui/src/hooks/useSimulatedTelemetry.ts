"use client";

import { useEffect, useState } from "react";

import { PIPELINE_TRANSCRIPT } from "@/data/pipelineTranscriptContent";

export type LogLevel = "info" | "warn" | "debug";

/** Banner rows mirror run_pipeline.py section headers (no [level] prefix in UI). */
export type TelemetryLine =
  | { kind: "banner"; text: string }
  | { kind: "plain"; text: string }
  | { kind: "log"; t: string; level: LogLevel; text: string };

export const BANNER_LINE = "============================================================";

/** Map raw stdout lines; promote === and `Pipeline: Section` rows to banner for section pauses. */
function promoteBanners(lines: TelemetryLine[]): TelemetryLine[] {
  return lines.map((ln) => {
    if (ln.kind !== "plain") return ln;
    if (ln.text === BANNER_LINE) return { kind: "banner", text: ln.text };
    const t = ln.text;
    if (t.trim().startsWith("Pipeline: Section")) {
      return { kind: "banner", text: t };
    }
    return ln;
  });
}

/**
 * Realistic pipeline transcript (see `src/data/pipelineTranscript.txt`).
 * Swap for SSE later without changing the terminal shell.
 */
function buildPipelineScript(): TelemetryLine[] {
  const raw = PIPELINE_TRANSCRIPT.split(/\r?\n/);
  const lines: TelemetryLine[] = raw.map((text) => ({
    kind: "plain",
    text,
  }));
  return promoteBanners(lines);
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
/** Short gap so long transcripts (~200+ lines) finish in ~30–45s. */
const PLAIN_LINE_MS = 70;

function delay(ms: number) {
  return new Promise<void>((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

/** Async paced orchestrator log — section headers pause before body lines. */
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
            await delay(PLAIN_LINE_MS);
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
