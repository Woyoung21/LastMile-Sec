"use client";

import { useEffect, useMemo, useState } from "react";

import { useRemediation } from "@/context/RemediationContext";
import { fetchLatestPacket } from "@/lib/api";
import { parseStepNumbersFromIssues } from "@/lib/selfrag";
import type { Finding, RemediatedPacket, RemediationBlock } from "@/types/lastmile";

export default function RemediationPage() {
  const { isRemediated, setRemediated } = useRemediation();
  const [packet, setPacket] = useState<RemediatedPacket | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [findingIdx, setFindingIdx] = useState(0);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetchLatestPacket("remediated");
        if (!cancelled) setPacket(res.data);
      } catch (e) {
        if (!cancelled)
          setErr(e instanceof Error ? e.message : "Failed to load remediated packet");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const finding: Finding | undefined = packet?.findings[findingIdx];
  const remediation: RemediationBlock | undefined = finding?.metadata?.remediation;

  const flaggedSteps = useMemo(() => {
    const vr = remediation?.selfrag_verification;
    if (!vr || vr.passed !== false) return new Set<number>();
    return parseStepNumbersFromIssues(vr.issues ?? []);
  }, [remediation]);

  return (
    <div className="space-y-8 py-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
          Remediation <span className="text-accent">action center</span>
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted sm:text-base">
          Copy-ready commands for L1/L2 operators. Executive summary first; each step lists
          rationale and exact actions. Self-RAG warnings surface when verification does not pass.
        </p>
      </div>

      {loading && (
        <p className="text-sm text-muted">Loading remediation runbooks…</p>
      )}
      {err && (
        <div className="rounded-lg border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-warn">
          {err}
        </div>
      )}

      {packet && packet.findings.length > 0 && finding && (
        <div className="flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-center sm:gap-6">
          <div className="flex min-w-0 flex-wrap items-center gap-3">
            <label className="text-sm text-muted" htmlFor="finding-select">
              Finding
            </label>
            <select
              id="finding-select"
              value={findingIdx}
              onChange={(e) => setFindingIdx(Number(e.target.value))}
              className="max-w-full rounded-md border border-surface-border bg-surface px-3 py-2 text-sm text-foreground"
            >
              {packet.findings.map((f, i) => (
                <option key={f.id} value={i}>
                  {f.title.slice(0, 80)}
                  {f.title.length > 80 ? "…" : ""}
                </option>
              ))}
            </select>
          </div>
          <label className="flex cursor-pointer items-center gap-3 rounded-lg border border-accent/35 bg-surface/70 px-4 py-3 shadow-sm transition-colors hover:border-accent/60">
            <input
              type="checkbox"
              className="h-4 w-4 shrink-0 rounded border-surface-border accent-[#00E5FF]"
              checked={isRemediated(finding.id)}
              onChange={(e) => setRemediated(finding.id, e.target.checked)}
            />
            <span className="text-sm font-semibold tracking-tight text-foreground">
              Mark as remediated
            </span>
          </label>
        </div>
      )}

      {remediation && (
        <div className="space-y-10">
          {remediation.selfrag_verification?.passed === false && (
            <div className="rounded-lg border border-warn/50 bg-warn/10 px-4 py-3 text-sm text-warn">
              <strong className="font-semibold">Self-RAG:</strong> runbook did not pass automated
              verification — review highlighted steps and issues below.
            </div>
          )}

          <section>
            <h2 className="mb-2 text-xs font-bold uppercase tracking-wider text-muted">
              Executive summary
            </h2>
            <p className="max-w-4xl text-base leading-relaxed text-foreground/90">
              {remediation.executive_summary}
            </p>
          </section>

          <section className="space-y-8">
            <h2 className="text-xs font-bold uppercase tracking-wider text-muted">Steps</h2>
            {(remediation.steps ?? []).map((step) => {
              const num = step.step_number ?? 0;
              const flagged = flaggedSteps.has(num);
              return (
                <article
                  key={num}
                  className={`rounded-xl border p-6 transition-colors ${flagged ? "border-warn bg-warn/5" : "border-surface-border bg-surface/40"}`}
                >
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="font-mono text-xs text-accent">
                      Step {step.step_number}
                    </span>
                    {step.step_type && (
                      <span className="rounded bg-surface px-2 py-0.5 text-[10px] uppercase text-muted">
                        {step.step_type}
                      </span>
                    )}
                    {flagged && (
                      <span className="rounded bg-warn/20 px-2 py-0.5 text-[10px] font-medium text-warn">
                        Self-RAG
                      </span>
                    )}
                  </div>
                  <h3 className="mt-2 text-lg font-semibold text-foreground">
                    {step.title}
                  </h3>
                  {step.command_or_action && (
                    <pre className="mt-4 overflow-x-auto rounded-lg border border-surface-border bg-black/60 p-4 font-mono text-sm text-foreground/95">
                      {step.command_or_action}
                    </pre>
                  )}
                  {step.explanation && (
                    <p className="mt-4 text-sm leading-relaxed text-muted">{step.explanation}</p>
                  )}
                  {step.substeps && step.substeps.length > 0 && (
                    <ol className="mt-4 list-decimal space-y-2 pl-5 text-sm text-foreground/85">
                      {step.substeps.map((sub, i) => (
                        <li key={i} className="leading-relaxed">
                          {sub}
                        </li>
                      ))}
                    </ol>
                  )}
                </article>
              );
            })}
          </section>

          {remediation.selfrag_verification &&
            remediation.selfrag_verification.issues?.length > 0 && (
              <section>
                <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted">
                  Verification issues
                </h2>
                <ul className="space-y-2 text-sm text-muted">
                  {remediation.selfrag_verification.issues.map((iss, i) => (
                    <li key={i} className="rounded border border-surface-border bg-black/30 px-3 py-2">
                      <span className="text-warn">[{iss.severity}]</span> {iss.message}
                    </li>
                  ))}
                </ul>
              </section>
            )}
        </div>
      )}

      {!loading && !err && !remediation && packet && (
        <p className="text-sm text-muted">No remediation metadata on this finding.</p>
      )}
    </div>
  );
}
