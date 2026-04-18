"use client";

import { useEffect, useRef } from "react";
import type { JobState } from "@/context/JobContext";

/** Advances simulated job progress while `active` (upload page). */
export function useJobTicker(
  active: boolean,
  onTick: (updater: (j: JobState) => JobState) => void,
) {
  const cb = useRef(onTick);
  cb.current = onTick;

  useEffect(() => {
    if (!active) return;
    const id = window.setInterval(() => {
      cb.current?.((j) => {
        if (!j.active || j.progress >= 100) return j;
        const n = Math.min(100, j.progress + Math.floor(3 + Math.random() * 8));
        let stage = j.stage;
        let message = j.message;
        if (n < 28) {
          stage = "Ingestion";
          message = "Stream parsing — fingerprinting hosts…";
        } else if (n < 52) {
          stage = "Mapping";
          message = "MITRE mapper — vector retrieval…";
        } else if (n < 78) {
          stage = "Correlation";
          message = "Vendor control fusion & scoring…";
        } else {
          stage = "Remediation";
          message = "Runbook synthesis — Self-RAG checks…";
        }
        return { ...j, progress: n, stage, message };
      });
    }, 1100);
    return () => window.clearInterval(id);
  }, [active]);
}
