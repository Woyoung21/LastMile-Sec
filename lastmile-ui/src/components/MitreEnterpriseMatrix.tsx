"use client";

import {
  ENTERPRISE_TACTICS_14,
  orphanTechniquesFromIds,
  techniquesByTactic,
  type MitreTactic,
} from "@/lib/mitreMatrix";

export type TechniqueCellStyle = "neutral" | "red" | "green";

export interface TechniqueCellState {
  style: TechniqueCellStyle;
  totalCount: number;
  remediatedCount: number;
}

const STYLE: Record<TechniqueCellStyle, string> = {
  neutral: "border-surface-border bg-black/40 text-foreground/80",
  red: "border-red-500 bg-red-500/10 text-red-500 shadow-[0_0_0_1px_rgba(239,68,68,0.35)]",
  green:
    "border-green-500 bg-green-500/10 text-green-500 shadow-[0_0_0_1px_rgba(34,197,94,0.35)]",
};

const TACTIC_HEADER_SHORT: Record<string, string> = {
  Reconnaissance: "RECON",
  "Resource Development": "RES.DEV",
  "Initial Access": "INIT.ACC",
  Execution: "EXEC",
  Persistence: "PERSIST",
  "Privilege Escalation": "PRIV.ESC",
  "Defense Evasion": "DEF.EVA",
  "Credential Access": "CRED",
  Discovery: "DISC",
  "Lateral Movement": "LAT.MOV",
  Collection: "COLL",
  "Command and Control": "C2",
  Exfiltration: "EXFIL",
  Impact: "IMPACT",
  Unmapped: "UNMAP",
};

function tacticHeader(tactic: MitreTactic): string {
  return TACTIC_HEADER_SHORT[tactic] ?? tactic.slice(0, 8);
}

function truncateName(name: string, max = 22): string {
  const t = name.trim();
  if (t.length <= max) return t;
  return `${t.slice(0, max - 1)}…`;
}

export function MitreEnterpriseMatrix({
  getTechniqueCellState,
  packetMitreIds,
}: {
  getTechniqueCellState: (techniqueId: string) => TechniqueCellState;
  packetMitreIds: Set<string>;
}) {
  const orphans = orphanTechniquesFromIds(packetMitreIds);
  const byTactic = techniquesByTactic(orphans);
  const unmappedCount = byTactic.get("Unmapped")?.length ?? 0;
  const showUnmapped = unmappedCount > 0;

  const columnTactics: MitreTactic[] = showUnmapped
    ? [...ENTERPRISE_TACTICS_14, "Unmapped"]
    : [...ENTERPRISE_TACTICS_14];

  const colCount = columnTactics.length;

  return (
    <div className="min-h-0 min-w-0 flex-1 overflow-x-auto overflow-y-hidden rounded-lg border border-surface-border bg-surface/40 shadow-inner">
      <div
        className="grid gap-1 px-1 py-1"
        style={{
          gridTemplateColumns: `repeat(${colCount}, minmax(52px, 1fr))`,
          minWidth: `${colCount * 56}px`,
        }}
      >
        {columnTactics.map((tactic) => {
          const list = byTactic.get(tactic) ?? [];
          return (
            <div
              key={tactic}
              className="flex min-h-0 min-w-0 flex-col gap-0.5"
            >
              <div
                className="truncate pb-1 text-center text-[9px] font-bold uppercase leading-tight tracking-tighter text-muted"
                title={tactic}
              >
                {tacticHeader(tactic)}
              </div>
              <div className="flex min-h-0 flex-1 flex-col gap-1 overflow-y-auto">
                {list.map((tech) => {
                  const cell = getTechniqueCellState(tech.id);
                  const { style: st, totalCount, remediatedCount } = cell;
                  const base = `${tech.id} – ${truncateName(tech.name, 28)}`;
                  const progressSuffix =
                    st !== "neutral" && totalCount > 1
                      ? ` [${remediatedCount}/${totalCount}]`
                      : "";
                  const label = `${base}${progressSuffix}`;
                  return (
                    <div
                      key={`${tactic}-${tech.id}-${tech.name}`}
                      title={`${tech.id} — ${tech.name}${progressSuffix ? ` — ${remediatedCount}/${totalCount} remediated` : ""}`}
                      className={`min-h-0 max-w-full rounded border p-1 text-[9px] leading-tight transition-colors ${STYLE[st]} ${progressSuffix ? "whitespace-normal break-words" : "truncate"}`}
                    >
                      {label}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
