"use client";

import { useJob } from "@/context/JobContext";

export function JobPill() {
  const { job } = useJob();
  if (!job.active || !job.id) return null;

  const short = `${job.id.slice(0, 8)}…`;

  return (
    <div className="flex max-w-[220px] items-center gap-2 rounded-full border border-surface-border bg-surface/80 px-3 py-1.5 text-[11px] text-muted backdrop-blur sm:max-w-xs">
      <span
        className="h-2 w-2 shrink-0 animate-pulse rounded-full bg-accent shadow-[0_0_8px_#00E5FF]"
        aria-hidden
      />
      <span className="truncate font-medium tracking-wide text-foreground/90">
        AI PROCESSING
      </span>
      <span className="truncate font-mono text-[10px] text-accent">job:{short}</span>
    </div>
  );
}
