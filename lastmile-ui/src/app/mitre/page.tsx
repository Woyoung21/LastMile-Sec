"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import {
  MitreEnterpriseMatrix,
  type TechniqueCellState,
} from "@/components/MitreEnterpriseMatrix";
import { useRemediation } from "@/context/RemediationContext";
import { fetchLatestPacket } from "@/lib/api";
import type { Finding, RemediatedPacket } from "@/types/lastmile";

function truncateFindingId(id: string): string {
  if (id.length <= 14) return id;
  return `${id.slice(0, 8)}…`;
}

/** Normalize MITRE id strings: trim + uppercase (packet casing may vary). */
function normMid(s: string): string {
  return String(s).trim().toUpperCase();
}

function normFindingId(s: string): string {
  return String(s).trim();
}

export default function MitrePage() {
  const { isRemediated, remediationVersion } = useRemediation();
  const [packet, setPacket] = useState<RemediatedPacket | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

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

  const mitreIdToFindingIds = useMemo(() => {
    const m = new Map<string, Set<string>>();
    if (!packet) return m;
    for (const f of packet.findings) {
      const fid = normFindingId(f.id);
      const ids = f.metadata?.mitre_mapping?.mitre_ids;
      if (!ids?.length) continue;
      for (const raw of ids) {
        const mid = normMid(raw);
        if (!mid) continue;
        if (!m.has(mid)) m.set(mid, new Set());
        m.get(mid)!.add(fid);
      }
    }
    return m;
  }, [packet]);

  const packetMitreIds = useMemo(
    () => new Set(mitreIdToFindingIds.keys()),
    [mitreIdToFindingIds],
  );

  const getTechniqueCellState = useCallback(
    (techniqueId: string): TechniqueCellState => {
      void remediationVersion;
      const tid = normMid(techniqueId);
      if (!mitreIdToFindingIds.has(tid)) {
        return { style: "neutral", totalCount: 0, remediatedCount: 0 };
      }
      const linked = mitreIdToFindingIds.get(tid);
      if (!linked?.size) {
        return { style: "neutral", totalCount: 0, remediatedCount: 0 };
      }
      const associatedFindingIds = [...linked];
      const totalCount = associatedFindingIds.length;
      const remediatedCount = associatedFindingIds.filter((id) =>
        isRemediated(id),
      ).length;
      const allRemediated =
        totalCount > 0 && remediatedCount === totalCount;
      return {
        style: allRemediated ? "green" : "red",
        totalCount,
        remediatedCount,
      };
    },
    [mitreIdToFindingIds, isRemediated, remediationVersion],
  );

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
          MITRE <span className="text-attack">ATT&amp;CK</span> mapper
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted sm:text-base">
          Vulnerability narratives ↔ enterprise techniques. Mapped techniques highlight{" "}
          <span className="text-red-500">red</span> until every linked finding is marked
          remediated (<span className="text-green-500">green</span>).
          {` `}
          Multi-finding techniques show progress{" "}
          <span className="font-mono text-[11px] text-foreground/80">[n/m]</span>.
        </p>
      </div>

      {loading && (
        <p className="text-sm text-muted">Loading latest remediated packet…</p>
      )}
      {err && (
        <div className="rounded-lg border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-warn">
          {err}{" "}
          <span className="text-muted">
            (set <code className="font-mono text-accent">NEXT_PUBLIC_API_BASE_URL</code> and run
            the sidecar)
          </span>
        </div>
      )}

      <div className="flex min-h-0 flex-col gap-6 lg:flex-row lg:gap-8">
        <section className="flex w-full shrink-0 flex-col lg:w-80 lg:max-h-[min(70vh,800px)] lg:overflow-y-auto lg:pr-4">
          <h2 className="mb-3 shrink-0 text-xs font-bold uppercase tracking-wider text-muted">
            Vulnerability cards
          </h2>
          <div className="custom-scroll flex min-h-0 flex-col gap-3 overflow-y-auto pr-1">
            {!packet?.findings.length && !loading ? (
              <p className="text-sm text-muted">No findings available.</p>
            ) : (
              packet?.findings.map((f: Finding) => {
                const mids = f.metadata?.mitre_mapping?.mitre_ids ?? [];
                const body =
                  f.metadata?.technical_summary?.trim() || "—";
                return (
                  <article
                    key={f.id}
                    className="rounded-lg border border-surface-border bg-surface/50 p-4"
                  >
                    <p className="font-mono text-[11px] text-accent">
                      id: {truncateFindingId(f.id)}
                    </p>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {mids.length === 0 ? (
                        <span className="text-xs text-muted">MITRE: —</span>
                      ) : (
                        mids.map((mid) => (
                          <span
                            key={mid}
                            className="rounded border border-surface-border bg-black/40 px-2 py-0.5 font-mono text-[10px] text-foreground/90"
                          >
                            {mid}
                          </span>
                        ))
                      )}
                    </div>
                    <p className="mt-3 text-sm leading-relaxed text-foreground/90">{body}</p>
                  </article>
                );
              })
            )}
          </div>
        </section>

        <section className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
          <h2 className="mb-3 shrink-0 text-xs font-bold uppercase tracking-wider text-muted">
            Enterprise matrix
          </h2>
          <div className="min-h-0 flex-1">
            <MitreEnterpriseMatrix
              getTechniqueCellState={getTechniqueCellState}
              packetMitreIds={packetMitreIds}
            />
          </div>
        </section>
      </div>
    </div>
  );
}
