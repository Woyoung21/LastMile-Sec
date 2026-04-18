/**
 * Enterprise ATT&CK-style matrix: static catalog from src/data/enterprise-techniques.json
 * plus explicit fallbacks for packet IDs not yet in the bundle.
 */

import enterpriseJson from "@/data/enterprise-techniques.json";

export const MITRE_TACTICS_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
  "Unmapped",
] as const;

/** First 14 tactics (Enterprise matrix); Unmapped is separate. */
export const ENTERPRISE_TACTICS_14 = MITRE_TACTICS_ORDER.slice(0, 14);

export type MitreTactic = (typeof MITRE_TACTICS_ORDER)[number];

export interface MatrixTechnique {
  id: string;
  name: string;
  tactic: MitreTactic;
}

/** Explicit tactic routing for IDs missing from enterprise-techniques.json. */
const TECHNIQUE_TACTIC_FALLBACK: MatrixTechnique[] = [
  { id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access" },
  { id: "T1059.004", name: "Unix Shell", tactic: "Execution" },
  { id: "T1021.004", name: "SSH", tactic: "Lateral Movement" },
];

function mergeCatalog(): MatrixTechnique[] {
  const fromJson: MatrixTechnique[] = (
    enterpriseJson as { id: string; name: string; tactic: string }[]
  ).map((row) => ({
    id: row.id,
    name: row.name,
    tactic: row.tactic as MitreTactic,
  }));
  const keys = new Set(fromJson.map((t) => `${t.tactic}::${t.id}`));
  const out = [...fromJson];
  for (const t of TECHNIQUE_TACTIC_FALLBACK) {
    const k = `${t.tactic}::${t.id}`;
    if (!keys.has(k)) {
      keys.add(k);
      out.push(t);
    }
  }
  return out;
}

export const MITRE_TECHNIQUES: MatrixTechnique[] = mergeCatalog();

const KNOWN_MITRE_IDS = new Set(MITRE_TECHNIQUES.map((t) => t.id));

export function techniquesByTactic(
  extras: MatrixTechnique[] = [],
): Map<MitreTactic, MatrixTechnique[]> {
  const map = new Map<MitreTactic, MatrixTechnique[]>();
  for (const t of MITRE_TACTICS_ORDER) map.set(t, []);
  const merged = [...MITRE_TECHNIQUES, ...extras];
  for (const tech of merged) {
    const col = map.get(tech.tactic);
    if (col) {
      const key = `${tech.tactic}::${tech.id}`;
      if (!col.some((x) => `${x.tactic}::${x.id}` === key)) {
        col.push(tech);
      }
    }
  }
  return map;
}

/** IDs present in the packet but not in the static catalog → Unmapped column. */
export function orphanTechniquesFromIds(ids: Iterable<string>): MatrixTechnique[] {
  const out: MatrixTechnique[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    if (seen.has(id)) continue;
    seen.add(id);
    if (KNOWN_MITRE_IDS.has(id)) continue;
    out.push({
      id,
      name: id,
      tactic: "Unmapped",
    });
  }
  return out;
}
