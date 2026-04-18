"use client";

import { useCallback, useId, useState } from "react";

import { TelemetryTerminal } from "@/components/TelemetryTerminal";
import { useJob } from "@/context/JobContext";
import { useJobTicker } from "@/hooks/useJobTicker";
import { useSimulatedTelemetry } from "@/hooks/useSimulatedTelemetry";

export default function UploadPage() {
  const { job, setJob, startSimulatedJob, resetJob } = useJob();
  const inputId = useId();
  const [drag, setDrag] = useState(false);
  const lines = useSimulatedTelemetry(job.active, job.id ?? undefined);

  useJobTicker(job.active, (fn) => setJob(fn));

  const onFiles = useCallback(() => {
    startSimulatedJob();
  }, [startSimulatedJob]);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
          Ingestion & <span className="text-accent">live telemetry</span>
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted sm:text-base">
          Stage raw evidence packages (PDF, CSV, PCAP) into the LastMile pipeline. The
          console streams operator-grade events — timestamps, parser stages, and mapper
          handoffs — as ingestion progresses.
        </p>
      </div>

      {!job.active ? (
        <label
          htmlFor={inputId}
          onDragOver={(e) => {
            e.preventDefault();
            setDrag(true);
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDrag(false);
            onFiles();
          }}
          className={`flex cursor-pointer flex-col items-center justify-center gap-4 rounded-xl border-2 border-dashed px-6 py-16 transition-colors ${drag ? "border-accent bg-accent/5" : "border-accent/40 bg-surface/30 hover:border-accent/70"}`}
        >
          <input
            id={inputId}
            type="file"
            className="sr-only"
            accept=".pdf,.csv,.pcap,.pcapng"
            multiple
            onChange={() => onFiles()}
          />
          <svg
            className="h-14 w-14 text-accent/90"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.25"
            aria-hidden
          >
            <path d="M12 3l8 6v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V9l8-6z" />
            <path d="M12 11v6M9 14h6" />
          </svg>
          <div className="text-center">
            <p className="text-lg font-medium text-foreground">Drop files to ingest</p>
            <p className="mt-1 text-sm text-muted">
              PDF · CSV · PCAP — or{" "}
              <span className="text-accent underline decoration-accent/50">Browse files</span>
            </p>
          </div>
        </label>
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="space-y-4 rounded-xl border border-surface-border bg-surface/40 p-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-muted">
                  Active job
                </p>
                <p className="mt-1 font-mono text-sm text-accent">{job.id}</p>
              </div>
              <button
                type="button"
                onClick={() => resetJob()}
                className="shrink-0 rounded-md border border-surface-border px-3 py-1 text-xs text-muted hover:border-accent hover:text-accent"
              >
                Reset
              </button>
            </div>
            <div>
              <p className="text-xs uppercase text-muted">Stage</p>
              <p className="text-lg font-medium text-foreground">{job.stage}</p>
            </div>
            <div>
              <div className="mb-1 flex justify-between text-xs text-muted">
                <span>Progress</span>
                <span>{job.progress}%</span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-black">
                <div
                  className="h-full bg-accent transition-[width] duration-500"
                  style={{ width: `${job.progress}%` }}
                />
              </div>
            </div>
            <p className="text-sm text-muted">{job.message}</p>
          </div>
          <TelemetryTerminal lines={lines} />
        </div>
      )}
    </div>
  );
}
