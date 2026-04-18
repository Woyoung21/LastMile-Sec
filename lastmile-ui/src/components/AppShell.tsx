"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { JobPill } from "@/components/JobPill";
import { ProgressStepper } from "@/components/ProgressStepper";

const NAV = [
  { href: "/upload", label: "Upload" },
  { href: "/mitre", label: "MITRE Map" },
  { href: "/remediation", label: "Remediation" },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="sticky top-0 z-30 border-b border-surface-border/80 bg-[#0a0a0a]/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] flex-col gap-4 px-4 py-4 lg:flex-row lg:items-center lg:justify-between lg:gap-6 lg:px-8">
          <div className="flex flex-wrap items-center gap-6">
            <Link href="/upload" className="flex shrink-0 items-baseline gap-0 font-semibold tracking-tight">
              <span className="text-lg text-foreground">LastMile</span>
              <span className="text-lg text-accent">Sec</span>
            </Link>
            <nav className="flex flex-wrap gap-1">
              {NAV.map((n) => {
                const on = pathname === n.href || pathname.startsWith(`${n.href}/`);
                return (
                  <Link
                    key={n.href}
                    href={n.href}
                    className={`rounded-md px-3 py-1.5 text-sm transition-colors ${on ? "bg-surface text-accent" : "text-muted hover:bg-surface hover:text-foreground"}`}
                  >
                    {n.label}
                  </Link>
                );
              })}
            </nav>
          </div>

          <div className="flex flex-1 flex-wrap items-center justify-center gap-4 lg:justify-center">
            <ProgressStepper />
          </div>

          <div className="flex justify-end lg:min-w-[200px]">
            <JobPill />
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-8 lg:px-8">
        {children}
      </main>
    </div>
  );
}
