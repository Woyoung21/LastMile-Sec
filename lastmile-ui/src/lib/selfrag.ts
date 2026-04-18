import type { SelfragIssue } from "@/types/lastmile";

/** Pull `Step N` references from self-RAG issue messages for step highlighting. */
export function parseStepNumbersFromIssues(issues: SelfragIssue[]): Set<number> {
  const steps = new Set<number>();
  const re = /Step\s+(\d+)/gi;
  for (const issue of issues) {
    let m: RegExpExecArray | null;
    const msg = issue.message;
    while ((m = re.exec(msg)) !== null) {
      steps.add(parseInt(m[1], 10));
    }
  }
  return steps;
}
