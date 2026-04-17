"""
Validation Layer for Section 2: Mapper Output Governance

Implements the three-gate validation pipeline from the Esposito thesis
(Chapter 4, Section 4.3):

    1. Format gate   -- output is a parseable list of ATT&CK IDs
    2. Consistency gate -- IDs are plausible given the input summary
    3. Policy gate   -- technique count, confidence, and tactic constraints

The layer sits between raw model output and the final MitreMappingResult,
adding structured rejection reasons and a ``validation_issues`` list that
can be forwarded to feedback / analyst review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .config import ATTACKMapperConfig


# ---------------------------------------------------------------------------
# Lightweight keyword-to-tactic heuristics for consistency checks.
# These are intentionally coarse -- they flag *obvious* mismatches,
# not subtle ones (which require a discriminative model, per the paper).
# ---------------------------------------------------------------------------

_TACTIC_KEYWORD_MAP: dict[str, set[str]] = {
    "initial-access": {
        "exploit", "phishing", "spearphish", "drive-by", "supply chain",
        "valid accounts", "default credentials", "public-facing",
        "vulnerable", "remote code execution", "rce", "injection",
        "overflow", "unauthenticated", "bypass",
        "end-of-life", "end of life", "eol", "unsupported", "outdated",
    },
    "execution": {
        "command", "script", "powershell", "cmd", "wmi", "scheduled task",
        "mshta", "regsvr32", "rundll32", "cscript", "wscript", "bash",
        "code execution", "rce", "overflow", "injection", "xss",
        "cross-site", "arbitrary code",
    },
    "persistence": {
        "registry", "run key", "startup", "scheduled task", "boot",
        "service", "cron", "implant", "backdoor", "web shell",
    },
    "credential-access": {
        "credential", "password", "brute force", "kerberoast", "lsass",
        "hash", "ntlm", "mimikatz", "keylog", "sniff",
        "authentication", "man-in-the-middle", "mitm", "cipher",
        "ssl", "tls", "certificate", "key exchange",
    },
    "lateral-movement": {
        "rdp", "remote desktop", "ssh", "smb", "psexec", "wmi",
        "lateral", "pivot", "pass the hash", "pass the ticket",
        "remote", "forwarded", "agent", "session",
    },
    "discovery": {
        "scan", "enumerate", "discovery", "recon", "port scan",
        "network scan", "service scan", "account discovery",
        "snmp", "community string", "version", "detection",
        "end-of-life", "eol", "deprecated", "software",
    },
    "command-and-control": {
        "c2", "beacon", "callback", "command and control", "dns tunnel",
        "encrypted channel", "proxy", "ingress tool",
        "cipher", "ssl", "tls", "encryption", "anonymous",
        "null cipher", "weak cipher",
    },
    "exfiltration": {
        "exfiltrat", "data transfer", "upload", "staging",
        "information leak", "disclosure", "expose",
    },
    "impact": {
        "denial of service", "dos", "ransomware", "encrypt", "wipe",
        "defacement", "destroy", "crash", "resource exhaustion",
        "fragmentation", "truncation",
    },
}

_TECHNIQUE_TACTIC_ROOTS: dict[str, list[str]] = {
    "T1566": ["initial-access"],
    "T1190": ["initial-access"],
    "T1189": ["initial-access"],
    "T1059": ["execution"],
    "T1203": ["execution"],
    "T1053": ["execution", "persistence"],
    "T1547": ["persistence"],
    "T1110": ["credential-access"],
    "T1003": ["credential-access"],
    "T1552": ["credential-access"],
    "T1556": ["credential-access"],
    "T1021": ["lateral-movement"],
    "T1563": ["lateral-movement"],
    "T1105": ["command-and-control", "lateral-movement"],
    "T1571": ["command-and-control"],
    "T1573": ["command-and-control"],
    "T1071": ["command-and-control"],
    "T1082": ["discovery"],
    "T1046": ["discovery"],
    "T1518": ["discovery"],
    "T1602": ["discovery", "credential-access"],
    "T1070": ["exfiltration"],
    "T1056": ["credential-access"],
    "T1205": ["command-and-control"],
    "T1080": ["lateral-movement"],
    "T1584": ["initial-access"],
    "T1102": ["command-and-control"],
    "T1567": ["exfiltration"],
    "T1486": ["impact"],
    "T1499": ["impact"],
    "T1498": ["impact"],
}


def summary_supports_t1190_fallback(technical_summary: str) -> bool:
    """True if the summary has Initial Access keyword overlap (Exploit Public-Facing Application context)."""
    if not technical_summary:
        return False
    sl = technical_summary.lower()
    keywords = _TACTIC_KEYWORD_MAP.get("initial-access", set())
    return any(kw in sl for kw in keywords)


def summary_supports_t1102_web_service_c2(summary: str) -> bool:
    """T1102 (Web Service) is a Command and Control technique.

    Require explicit C2 / covert-channel signals. Generic HTTP/HTTPS, nginx,
    or \"web server\" wording alone is insufficient (avoids Dead Drop Resolver
    false positives on scanner EOL findings).
    """
    if not summary:
        return False
    s = summary.lower()
    return bool(
        re.search(
            r"\b("
            r"c2|command and control|command-and-control|beacon|callback|"
            r"dead drop|drop resolver|dns tunnel|covert channel|ingress tool|"
            r"steganograph|covert comms|exfiltration channel"
            r")\b",
            s,
            re.I,
        )
    )


@dataclass
class ValidationIssue:
    """A single issue raised by the Validation Layer."""

    gate: str
    severity: str
    message: str
    technique_id: str | None = None


@dataclass
class ValidationResult:
    """Aggregate result of all three validation gates."""

    passed: bool = True
    issues: list[ValidationIssue] = field(default_factory=list)
    accepted_ids: list[str] = field(default_factory=list)
    rejected_ids: list[str] = field(default_factory=list)
    gate_results: dict[str, bool] = field(default_factory=dict)

    @property
    def issue_count(self) -> int:
        return len(self.issues)


class MappingValidator:
    """Three-gate validation layer for mapper output.

    Parameters
    ----------
    known_ids : set[str] | None
        Valid ATT&CK technique root IDs.  Defaults to the 18.1 registry.
    max_techniques : int
        Maximum techniques allowed per finding (policy gate).
    """

    def __init__(
        self,
        known_ids: set[str] | None = None,
        max_techniques: int = ATTACKMapperConfig.MAX_TECHNIQUES_PER_FINDING,
    ):
        self.known_ids = {
            tid.upper()
            for tid in (known_ids or ATTACKMapperConfig.DEFAULT_ENTERPRISE_18_1_TECHNIQUE_IDS)
        }
        self.max_techniques = max_techniques
        self._id_pattern = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

    def validate(
        self,
        candidate_ids: list[str],
        raw_model_output: str,
        technical_summary: str,
    ) -> ValidationResult:
        """Run all three gates and return an aggregate result."""
        result = ValidationResult()

        format_ok = self._gate_format(candidate_ids, raw_model_output, result)
        result.gate_results["format"] = format_ok

        semantic_ok = self._gate_semantic(technical_summary, result)
        result.gate_results["semantic"] = semantic_ok

        self._apply_t1190_fallback_if_needed(technical_summary, result)

        consistency_ok = self._gate_consistency(
            result.accepted_ids or candidate_ids,
            technical_summary,
            result,
        )
        result.gate_results["consistency"] = consistency_ok

        policy_ok = self._gate_policy(result.accepted_ids, result)
        result.gate_results["policy"] = policy_ok

        # Consistency gate is advisory -- it logs warnings but does not
        # block validation. Format, semantic, and policy gates are hard gates.
        result.passed = format_ok and semantic_ok and policy_ok
        return result

    # ------------------------------------------------------------------
    # Gate 1: Format
    # ------------------------------------------------------------------

    def _gate_format(
        self,
        candidate_ids: list[str],
        raw_model_output: str,
        result: ValidationResult,
    ) -> bool:
        """Verify every candidate is a well-formed, known ATT&CK ID."""
        if not candidate_ids and raw_model_output.strip():
            result.issues.append(
                ValidationIssue(
                    gate="format",
                    severity="warning",
                    message="Model produced output but no technique IDs were extracted.",
                )
            )

        ok = True
        for tid in candidate_ids:
            normalized = tid.upper()

            if not self._id_pattern.match(normalized):
                result.issues.append(
                    ValidationIssue(
                        gate="format",
                        severity="error",
                        message=f"Malformed technique ID: {tid!r}",
                        technique_id=tid,
                    )
                )
                result.rejected_ids.append(normalized)
                ok = False
                continue

            root = normalized.split(".", 1)[0]
            if root not in self.known_ids and normalized not in self.known_ids:
                result.issues.append(
                    ValidationIssue(
                        gate="format",
                        severity="error",
                        message=(
                            f"Unknown technique {normalized} -- not in "
                            f"ATT&CK Enterprise {ATTACKMapperConfig.ATTACK_VERSION}."
                        ),
                        technique_id=normalized,
                    )
                )
                result.rejected_ids.append(normalized)
                ok = False
                continue

            result.accepted_ids.append(normalized)

        return ok

    # ------------------------------------------------------------------
    # Gate 1b: Semantic (hard filter on known mis-mappings)
    # ------------------------------------------------------------------

    def _gate_semantic(self, technical_summary: str, result: ValidationResult) -> bool:
        """Drop technique IDs that contradict the summary (e.g. T1102 without C2 evidence)."""
        if not result.accepted_ids:
            return True

        kept: list[str] = []
        for tid in result.accepted_ids:
            root = tid.upper().split(".", 1)[0]
            if root == "T1102" and not summary_supports_t1102_web_service_c2(technical_summary):
                result.issues.append(
                    ValidationIssue(
                        gate="semantic",
                        severity="warning",
                        message=(
                            f"Rejected {tid}: Web Service (T1102) requires C2-like evidence in "
                            "the summary (not merely HTTP/HTTPS or a generic web server)."
                        ),
                        technique_id=tid,
                    )
                )
                result.rejected_ids.append(tid)
                continue
            kept.append(tid)

        result.accepted_ids = kept
        return True

    def _apply_t1190_fallback_if_needed(
        self, technical_summary: str, result: ValidationResult
    ) -> None:
        """If semantic gate removed T1102 only and nothing remains, suggest T1190 when the summary fits Initial Access."""
        if not ATTACKMapperConfig.T1102_FALLBACK_T1190:
            return
        if result.accepted_ids:
            return
        had_t1102_rejection = any(
            (tid or "").upper().split(".", 1)[0] == "T1102" for tid in result.rejected_ids
        )
        if not had_t1102_rejection:
            return
        if not summary_supports_t1190_fallback(technical_summary):
            return
        if "T1190" not in self.known_ids:
            return
        result.accepted_ids.append("T1190")
        result.issues.append(
            ValidationIssue(
                gate="fallback",
                severity="info",
                message=(
                    "Inferred T1190 after T1102 was rejected (no C2 evidence): summary matches "
                    "Initial Access heuristics (Exploit Public-Facing Application)."
                ),
                technique_id="T1190",
            )
        )

    # ------------------------------------------------------------------
    # Gate 2: Consistency
    # ------------------------------------------------------------------

    def _gate_consistency(
        self,
        accepted_ids: list[str],
        technical_summary: str,
        result: ValidationResult,
    ) -> bool:
        """Light heuristic: flag IDs whose tactic family has zero keyword
        overlap with the summary.  This catches obvious mismatches without
        requiring a trained discriminator."""
        if not accepted_ids or not technical_summary:
            return True

        summary_lower = technical_summary.lower()
        ok = True

        for tid in list(accepted_ids):
            root = tid.split(".", 1)[0]
            tactics = _TECHNIQUE_TACTIC_ROOTS.get(root)
            if not tactics:
                continue

            has_overlap = False
            for tactic in tactics:
                keywords = _TACTIC_KEYWORD_MAP.get(tactic, set())
                if any(kw in summary_lower for kw in keywords):
                    has_overlap = True
                    break

            if not has_overlap:
                result.issues.append(
                    ValidationIssue(
                        gate="consistency",
                        severity="warning",
                        message=(
                            f"{tid} ({', '.join(tactics)}) has no keyword support "
                            f"in the summary. May be a near-neighbor hallucination."
                        ),
                        technique_id=tid,
                    )
                )
                ok = False

        return ok

    # ------------------------------------------------------------------
    # Gate 3: Policy
    # ------------------------------------------------------------------

    def _gate_policy(
        self,
        accepted_ids: list[str],
        result: ValidationResult,
    ) -> bool:
        """Enforce configurable policy constraints."""
        ok = True

        if len(accepted_ids) > self.max_techniques:
            excess = accepted_ids[self.max_techniques:]
            result.issues.append(
                ValidationIssue(
                    gate="policy",
                    severity="warning",
                    message=(
                        f"Exceeded max techniques ({self.max_techniques}). "
                        f"Dropping: {', '.join(excess)}"
                    ),
                )
            )
            result.accepted_ids = accepted_ids[: self.max_techniques]
            ok = False

        return ok
