/** Stage and message for simulated job progress bands (upload page, aligned to transcript %). */
export function jobStageForProgress(progress: number): { stage: string; message: string } {
  if (progress < 28) {
    return {
      stage: "Ingestion",
      message: "Stream parsing — fingerprinting hosts…",
    };
  }
  if (progress < 52) {
    return { stage: "Mapping", message: "MITRE mapper — vector retrieval…" };
  }
  if (progress < 78) {
    return { stage: "Correlation", message: "Vendor control fusion & scoring…" };
  }
  return {
    stage: "Remediation",
    message: "Runbook synthesis — Self-RAG checks…",
  };
}
