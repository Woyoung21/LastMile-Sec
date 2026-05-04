"use client";

import { useEffect, useRef, useState } from "react";

import { PIPELINE_TRANSCRIPT } from "@/data/pipelineTranscriptContent";

export type LogLevel = "info" | "warn" | "debug";

/** Banner rows mirror run_pipeline.py section headers (no [level] prefix in UI). */
export type TelemetryLine =
  | { kind: "banner"; text: string }
  | { kind: "plain"; text: string }
  | { kind: "log"; t: string; level: LogLevel; text: string };

export const BANNER_LINE = "============================================================";

export type StreamProgressInfo = {
  lineIndex: number;
  lineCount: number;
  progress: number;
};

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

/** Section gaps vs plain line gaps, matching former 1750:70 ≈ 25:1. */
const SECTION_WEIGHT = 1750;
const PLAIN_WEIGHT = 70;

export const TARGET_TELEMETRY_MS = 60_000;

function buildGapDelaysMs(script: TelemetryLine[], targetTotalMs: number): number[] {
  const n = script.length;
  if (n <= 1) return [];
  const ratio = SECTION_WEIGHT / PLAIN_WEIGHT;
  const weights: number[] = [];
  for (let i = 1; i < n; i++) {
    weights.push(needsSectionPauseBeforeIndex(script, i) ? ratio : 1);
  }
  const totalWeight = weights.reduce((a, w) => a + w, 0);
  if (totalWeight <= 0) return weights.map(() => 0);
  const unit = targetTotalMs / totalWeight;
  return weights.map((w) => w * unit);
}

function delay(ms: number) {
  return new Promise<void>((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

/** Async paced orchestrator log — section headers pause before body lines; total duration ≈ TARGET_TELEMETRY_MS. */
export function useSimulatedTelemetry(
  active: boolean,
  resetKey?: string,
  onStreamProgress?: (info: StreamProgressInfo) => void,
) {
  const [lines, setLines] = useState<TelemetryLine[]>([]);
  const onProgressRef = useRef(onStreamProgress);
  onProgressRef.current = onStreamProgress;

  useEffect(() => {
    if (!active) {
      setLines([]);
      return;
    }

    const script = buildPipelineScript();
    setLines([]);
    const gapDelays = buildGapDelaysMs(script, TARGET_TELEMETRY_MS);
    const lineCount = script.length;
    let cancelled = false;

    void (async () => {
      for (let i = 0; i < script.length; i++) {
        if (cancelled) return;
        if (i > 0) {
          await delay(gapDelays[i - 1] ?? 0);
        }
        if (cancelled) return;
        const row = script[i];
        setLines((prev) => [...prev, row].slice(-400));
        const progress =
          lineCount > 0 ? Math.min(100, Math.round((100 * (i + 1)) / lineCount)) : 100;
        onProgressRef.current?.({
          lineIndex: i,
          lineCount,
          progress,
        });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [active, resetKey]);

  return lines;
}
