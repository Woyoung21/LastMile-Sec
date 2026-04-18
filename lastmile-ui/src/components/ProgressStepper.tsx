"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const STAGES = [
  { label: "Ingestion", href: "/upload" },
  { label: "Mapping", href: "/mitre" },
  { label: "Correlation", href: "/mitre" },
  { label: "Remediation", href: "/remediation" },
] as const;

/** upload → active0; mitre → done0, active1; remediation → done0–2, active3 */
function derive(pathname: string): { doneBefore: number; active: number } {
  if (pathname.startsWith("/remediation")) return { doneBefore: 2, active: 3 };
  if (pathname.startsWith("/mitre")) return { doneBefore: 0, active: 1 };
  return { doneBefore: -1, active: 0 };
}

export function ProgressStepper() {
  const pathname = usePathname();
  const { doneBefore, active } = derive(pathname);

  return (
    <div className="flex flex-wrap items-center justify-center gap-1 sm:gap-2">
      {STAGES.map((stage, i) => {
        const done = i <= doneBefore;
        const current = i === active;
        return (
          <div key={stage.label} className="flex items-center gap-1 sm:gap-2">
            {i > 0 && (
              <div
                className={`hidden h-px w-3 sm:block ${done || current ? "bg-accent/45" : "bg-surface-border"}`}
              />
            )}
            <Link
              href={stage.href}
              className={`flex items-center gap-1.5 rounded-full px-0.5 py-0.5 text-[10px] font-medium uppercase tracking-wide sm:gap-2 sm:text-xs ${current ? "text-accent" : "text-muted"}`}
            >
              <span
                className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border-2 text-[9px] sm:h-8 sm:w-8 sm:text-[10px] ${done ? "border-accent/80 bg-accent/10 text-accent" : ""} ${current && !done ? "border-accent text-accent shadow-[0_0_12px_rgba(0,229,255,0.35)]" : ""} ${!done && !current ? "border-surface-border text-muted" : ""}`}
              >
                {done ? "✓" : i + 1}
              </span>
              <span className="max-w-[5.5rem] truncate sm:max-w-none">
                {stage.label}
              </span>
            </Link>
          </div>
        );
      })}
    </div>
  );
}
