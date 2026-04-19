/**
 * Generates high-density mockGraphData.json (~248 nodes). Run from lastmile-ui/: node scripts/gen-mock-graph-dense.mjs
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(__dirname, "..", "src", "data", "mockGraphData.json");

const frameworks = [
  {
    id: "fw-nist-800-53",
    label: "NIST SP 800-53",
    description:
      "NIST Special Publication 800-53 Rev 5 — security and privacy controls for federal and regulated systems (OSCAL catalog alignment).",
  },
  {
    id: "fw-cis-macos15",
    label: "CIS Apple macOS 15 (Sequoia)",
    description:
      "CIS Benchmark for Apple macOS 15 Sequoia — system integrity, Gatekeeper, FileVault, and enterprise management profiles.",
  },
  {
    id: "fw-cis-azure-ws2022",
    label: "CIS Azure Compute Windows Server 2022",
    description:
      "CIS Benchmark for Windows Server 2022 on Azure Compute — hardened images, Defender, and guest OS baselines.",
  },
  {
    id: "fw-cis-cisco-iosxe",
    label: "CIS Cisco IOS XE Switch L2S",
    description:
      "CIS STIG-aligned IOS XE L2 switching — AAA, SNMP, STP hardening, and management plane protection.",
  },
  {
    id: "fw-cis-chrome",
    label: "CIS Google Chrome",
    description:
      "CIS Google Chrome Benchmark — updates, Safe Browsing, extension policies, and enterprise cloud management.",
  },
  {
    id: "fw-cis-gcp",
    label: "CIS Google Cloud Platform Foundation",
    description:
      "CIS GCP Foundation — IAM separation, logging sinks, VPC controls, and storage public access prevention.",
  },
  {
    id: "fw-cis-infoblox",
    label: "CIS Infoblox 8.x DNS",
    description:
      "CIS STIG for Infoblox NIOS DNS — DNSSEC, zone transfers, admin RBAC, and audit logging.",
  },
  {
    id: "fw-cis-m365",
    label: "CIS Microsoft 365 Foundations",
    description:
      "CIS Microsoft 365 Foundations — Entra ID sign-in risk, Exchange Online, Teams, and SharePoint secure defaults.",
  },
  {
    id: "fw-cis-edge",
    label: "CIS Microsoft Edge",
    description:
      "CIS Microsoft Edge Benchmark — SmartScreen, password manager policies, and enterprise update channels.",
  },
  {
    id: "fw-cis-entra",
    label: "CIS Microsoft Entra ID",
    description:
      "CIS Microsoft Entra ID STIG — conditional access, PIM, legacy auth blocks, and guest lifecycle.",
  },
  {
    id: "fw-cis-win11",
    label: "CIS Microsoft Windows 11 STIG",
    description:
      "CIS Microsoft Windows 11 STIG — credential guard, BitLocker, Defender ASR rules, and local policy lockdown.",
  },
  {
    id: "fw-cis-firefox",
    label: "CIS Mozilla Firefox",
    description:
      "CIS Mozilla Firefox STIG — ESR updates, extension allowlists, and telemetry/telemetry opt-outs.",
  },
  {
    id: "fw-cis-paloalto",
    label: "CIS Palo Alto Firewall 11",
    description:
      "CIS Palo Alto Networks PAN-OS 11 — security profiles, log forwarding, admin MFA, and rule hygiene.",
  },
  {
    id: "fw-cis-ubuntu",
    label: "CIS Ubuntu Linux 24.04 LTS",
    description:
      "CIS Ubuntu Linux 24.04 LTS STIG — AppArmor, sshd, auditd, and unattended upgrades.",
  },
  {
    id: "fw-cis-vmware",
    label: "CIS VMware vSphere 8.0 ESXi",
    description:
      "CIS VMware vSphere 8.0 ESXi STIG — lockdown mode, TPM, certificate management, and vSphere permissions.",
  },
];

const mitrePool = [
  { id: "T1190", label: "T1190", description: "Exploit Public-Facing Application" },
  { id: "T1059.001", label: "T1059.001", description: "PowerShell" },
  { id: "T1059.004", label: "T1059.004", description: "Unix Shell" },
  { id: "T1078", label: "T1078", description: "Valid Accounts" },
  { id: "T1110", label: "T1110", description: "Brute Force" },
  { id: "T1021.001", label: "T1021.001", description: "Remote Desktop Protocol" },
  { id: "T1550.001", label: "T1550.001", description: "Application Access Token" },
  { id: "T1562.001", label: "T1562.001", description: "Disable or Modify Tools" },
  { id: "T1070.001", label: "T1070.001", description: "Clear Windows Event Logs" },
  { id: "T1486", label: "T1486", description: "Data Encrypted for Impact" },
  { id: "T1490", label: "T1490", description: "Inhibit System Recovery" },
  { id: "T1047", label: "T1047", description: "Windows Management Instrumentation" },
  { id: "T1547.001", label: "T1547.001", description: "Registry Run Keys" },
  { id: "T1136.001", label: "T1136.001", description: "Local Account" },
  { id: "T1098", label: "T1098", description: "Account Manipulation" },
  { id: "T1530", label: "T1530", description: "Data from Cloud Storage" },
  { id: "T1539", label: "T1539", description: "Steal Web Session Cookie" },
  { id: "T1552.001", label: "T1552.001", description: "Credentials In Files" },
  { id: "T1003.001", label: "T1003.001", description: "LSASS Memory" },
  { id: "T1213", label: "T1213", description: "Data from Information Repositories" },
  { id: "T1195.002", label: "T1195.002", description: "Compromise Software Supply Chain" },
  { id: "T1204.002", label: "T1204.002", description: "Malicious File" },
  { id: "T1566.001", label: "T1566.001", description: "Spearphishing Attachment" },
  { id: "T1027", label: "T1027", description: "Obfuscated Files or Information" },
  { id: "T1036.005", label: "T1036.005", description: "Match Legitimate Name or Location" },
  { id: "T1548.002", label: "T1548.002", description: "Bypass User Account Control" },
  { id: "T1068", label: "T1068", description: "Exploitation for Privilege Escalation" },
  { id: "T1083", label: "T1083", description: "File and Directory Discovery" },
  { id: "T1018", label: "T1018", description: "Remote System Discovery" },
  { id: "T1046", label: "T1046", description: "Network Service Scanning" },
  { id: "T1090", label: "T1090", description: "Proxy" },
  { id: "T1572", label: "T1572", description: "Protocol Tunneling" },
  { id: "T1499", label: "T1499", description: "Endpoint Denial of Service" },
  { id: "T1565.002", label: "T1565.002", description: "Transmitted Data Manipulation" },
  { id: "T1484.001", label: "T1484.001", description: "Group Policy Modification" },
  { id: "T1553.004", label: "T1553.004", description: "Install Root Certificate" },
  { id: "T1071.001", label: "T1071.001", description: "Web Protocols" },
  { id: "T1105", label: "T1105", description: "Ingress Tool Transfer" },
  { id: "T1218", label: "T1218", description: "Signed Binary Proxy Execution" },
  { id: "T1219", label: "T1219", description: "Remote Access Software" },
];

const CONTROLS_PER_FW = 15;
const M = mitrePool.length;

const NIST_CTRL_KEYS = [
  "AC-01",
  "AC-02",
  "AC-03",
  "AU-02",
  "CM-06",
  "CM-07",
  "IA-05",
  "SC-07",
  "SI-02",
  "SI-04",
  "RA-05",
  "MP-02",
  "PE-03",
  "PL-04",
  "CP-09",
];

function controlDescription(fw, idx) {
  return (
    `${fw.label} — control bundle ${idx + 1}.\n\n` +
    `Apply benchmark intent: restrict administrative interfaces, remove unnecessary services, enforce MFA where available, ` +
    `and maintain auditable configuration drift checks for [ASSIGNMENT: scope]. ` +
    `Validate during [ASSIGNMENT: window]; remediate with rollback-tested changes.`
  );
}

const nodes = [];
const links = [];

for (const f of frameworks) {
  nodes.push({
    id: f.id,
    group: "Framework",
    label: f.label,
    description: f.description,
  });
}

for (const m of mitrePool) {
  nodes.push({
    id: m.id,
    group: "MITRE",
    label: m.label,
    description: m.description,
  });
}

let globalIdx = 0;
for (let fi = 0; fi < frameworks.length; fi++) {
  const fw = frameworks[fi];
  for (let i = 0; i < CONTROLS_PER_FW; i++) {
    const cid = `ctl-${fw.id}-${i}`;
    const short =
      fw.id === "fw-nist-800-53"
        ? `NIST-${NIST_CTRL_KEYS[i % NIST_CTRL_KEYS.length]}`
        : `CIS-${fi + 1}.${i + 1}.${(i + fi) % 8 + 1}`;
    nodes.push({
      id: cid,
      group: "Control",
      label: short,
      description: controlDescription(fw, i),
    });
    links.push({ source: fw.id, target: cid });
    const a = (globalIdx * 7 + fi * 3) % M;
    const b = (globalIdx * 11 + i * 5 + 13) % M;
    const c = (globalIdx * 17 + fi + i) % M;
    links.push({ source: cid, target: mitrePool[a].id });
    links.push({ source: cid, target: mitrePool[b].id });
    if (globalIdx % 2 === 0) links.push({ source: cid, target: mitrePool[c].id });
    globalIdx++;
  }
}

const data = { nodes, links };
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(data, null, 2), "utf8");
console.log(`Wrote ${nodes.length} nodes, ${links.length} links → ${out}`);
