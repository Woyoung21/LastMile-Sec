"use client";

import { useEffect, useRef } from "react";

import type { TelemetryLine } from "@/hooks/useSimulatedTelemetry";

const levelClass: Record<string, string> = {
  info: "text-accent",
  warn: "text-warn",
  debug: "text-log-debug",
};

export function TelemetryTerminal({ lines }: { lines: TelemetryLine[] }) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [lines]);

  return (
    <div className="flex h-96 max-h-[500px] min-h-[240px] flex-col rounded-lg border border-surface-border bg-black font-mono text-xs shadow-[0_0_15px_rgba(0,229,255,0.1)] shadow-inner">
      <div className="flex shrink-0 items-center gap-2 border-b border-surface-border px-3 py-2">
        <span className="inline-flex gap-1.5">
          <span className="h-3 w-3 rounded-full bg-[#ff5f56]" aria-hidden />
          <span className="h-3 w-3 rounded-full bg-[#febc2e]" aria-hidden />
          <span className="h-3 w-3 rounded-full bg-[#28c840]" aria-hidden />
        </span>
        <span className="text-muted">telemetry</span>
      </div>
      <div
        ref={scrollRef}
        className="custom-scroll flex-1 overflow-y-auto overflow-x-auto px-3 pb-4 pt-3 leading-[1.65] text-foreground/90"
      >
        {lines.length === 0 ? (
          <p className="text-log-debug">Awaiting job…</p>
        ) : (
          lines.map((ln, i) =>
            ln.kind === "banner" ? (
              <div
                key={`banner-${i}`}
                className="whitespace-pre-wrap break-all text-foreground/90"
              >
                {ln.text}
              </div>
            ) : (
              <div
                key={`log-${ln.t}-${i}`}
                className="whitespace-pre-wrap break-all"
              >
                <span className="text-muted">{ln.t}</span>{" "}
                <span className={levelClass[ln.level] ?? "text-muted"}>
                  [{ln.level}]
                </span>{" "}
                <span className="text-foreground/85">{ln.text}</span>
              </div>
            ),
          )
        )}
      </div>
    </div>
  );
}
