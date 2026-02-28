"""
Reporter Model for Section 2

Takes normalized JSON packets from Section 1 and generates:
1. Technical summary sentences via Gemini LLM
2. Enriched packets ready for MITRE ATT&CK mapping
"""

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Optional

import google.genai

from .config import ReporterConfig
from .prompts import SummaryPrompts


class Reporter:
    """
    Reporter Model for generating technical summaries from security findings.

    Workflow:
    1. Load JSON packet (from Section 1 output)
    2. For each finding, generate a technical summary sentence
    3. Store summary in finding metadata
    4. Output enriched packet ready for Section 3 (ATT&CK mapping)
    """

    def __init__(
        self,
        client=None,
        cache_dir: Path | None = None,
        enable_cache: bool | None = None,
        sleep_seconds_between_requests: float | None = None,
    ):
        """Initialize Reporter with Gemini API or an injected test client."""
        self.cache_dir = cache_dir or ReporterConfig.CACHE_DIR
        self.enable_cache = ReporterConfig.ENABLE_CACHE if enable_cache is None else enable_cache
        self.sleep_seconds_between_requests = (
            1.0 if sleep_seconds_between_requests is None else sleep_seconds_between_requests
        )
        self._last_summary_source = "unknown"

        if self.enable_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

        if client is not None:
            self.client = client
        else:
            ReporterConfig.ensure_cache_dir()
            if not ReporterConfig.validate():
                raise ValueError("Reporter configuration validation failed")
            self.client = google.genai.Client(api_key=ReporterConfig.GEMINI_API_KEY)

        self.report_count = 0
        self.cache_hits = 0
        self.cache_misses = 0

    def _normalize_title(self, title: str) -> str:
        """Strip scoring metadata from titles before prompt reuse."""
        if not title:
            return ""

        normalized = re.sub(r"\s*\(CVSS:\s*[^)]+\)\s*$", "", title, flags=re.IGNORECASE)
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized.strip()

    def _sanitize_summary_text(self, summary: str) -> str:
        """Normalize whitespace and repeated punctuation."""
        cleaned = re.sub(r"\s+", " ", (summary or "").strip())
        cleaned = re.sub(r"\s+([,.;:])", r"\1", cleaned)
        cleaned = re.sub(r"([.?!]){2,}", r"\1", cleaned)
        return cleaned.strip()

    def _get_cache_key(self, finding_dict: dict) -> str:
        """Generate a strong cache key for a finding."""
        metadata = finding_dict.get("metadata", {})

        cache_payload = {
            "prompt_version": ReporterConfig.SUMMARY_PROMPT_VERSION,
            "model": ReporterConfig.GEMINI_MODEL,
            "title": self._normalize_title(finding_dict.get("title", "")),
            "description": finding_dict.get("description", ""),
            "raw_excerpt": finding_dict.get("raw_excerpt", "")[:2000],
            "cve_ids": finding_dict.get("cve_ids", []),
            "services": metadata.get("services", []),
            "ports": metadata.get("ports", []),
        }

        raw = json.dumps(cache_payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _load_from_cache(self, cache_key: str) -> Optional[str]:
        """Load summary from cache if available."""
        if not self.enable_cache:
            return None

        cache_file = self.cache_dir / f"{cache_key}.txt"
        if cache_file.exists():
            self.cache_hits += 1
            return cache_file.read_text(encoding="utf-8").strip()

        self.cache_misses += 1
        return None

    def _save_to_cache(self, cache_key: str, summary: str):
        """Save a validated LLM summary to cache."""
        if not self.enable_cache:
            return

        cache_file = self.cache_dir / f"{cache_key}.txt"
        cache_file.write_text(summary, encoding="utf-8")

    def _extract_reporter_evidence(self, finding_dict: dict) -> dict:
        """Extract the highest-signal evidence for the reporter prompt."""
        metadata = finding_dict.get("metadata", {})
        title = self._normalize_title(finding_dict.get("title", "Unknown finding"))
        description = finding_dict.get("description", "")
        raw_excerpt = finding_dict.get("raw_excerpt", "")

        # Prefer raw_excerpt because it often contains the exploit mechanic
        # in the "Impact" or "Vulnerability Insight" sections.
        evidence_text = raw_excerpt[:2500] if raw_excerpt else description[:1000]

        return {
            "title": title,
            "description": description,
            "evidence_text": evidence_text,
            "cves": ", ".join(finding_dict.get("cve_ids", [])) or "N/A",
            "services": ", ".join(metadata.get("services", [])) or "Unknown",
            "ports": ", ".join(metadata.get("ports", [])) or "Unknown",
        }

    def _is_valid_summary(self, summary: str) -> bool:
        """Validate that the summary is usable and not obvious junk."""
        if not summary or not isinstance(summary, str):
            return False

        cleaned = self._sanitize_summary_text(summary)
        word_count = len(cleaned.split())
        if word_count < 8 or word_count > 50:
            return False

        if not cleaned.endswith("."):
            return False

        terminal_endings = len(re.findall(r"[.!?](?:\s|$)", cleaned))
        if terminal_endings != 1:
            return False

        banned_patterns = [
            r"\bCVSS\b",
            r"\bseverity\b",
            r"\bhigh-severity\b",
            r"\bmedium-severity\b",
            r"\bcritical-severity\b",
            r"^\s*\[(critical|high|medium|low|info|informational)\]",
            r"\bmultiple vulnerabilities\b",
            r"\bmultiple security flaws\b",
            r"\bunspecified\b",
            r"\bas tracked by\b",
            r"\bresulting in a .* severity\b",
        ]
        for pattern in banned_patterns:
            if re.search(pattern, cleaned, flags=re.IGNORECASE):
                return False

        return True

    def _build_fallback_summary(self, finding_dict: dict) -> str:
        """Build a deterministic fallback summary when LLM output is unusable."""
        title = self._normalize_title((finding_dict.get("title", "") or "").strip())
        cves = finding_dict.get("cve_ids", []) or []
        cve_text = cves[0] if cves else None

        metadata = finding_dict.get("metadata", {})
        services = metadata.get("services", []) or []
        service_text = services[0] if services else None

        if cve_text and service_text:
            summary = f"{title} affects the {service_text} service and is associated with {cve_text}."
        elif cve_text:
            summary = f"{title} is associated with {cve_text}."
        elif service_text:
            summary = f"{title} affects the {service_text} service."
        elif title:
            summary = f"{title} affects the target system."
        else:
            summary = "The finding indicates a security-relevant condition on the target system."

        return self._sanitize_summary_text(summary)

    def _generate_summary_result(self, finding_dict: dict) -> tuple[str, bool, str]:
        """Generate a summary and report whether it came from cache, llm, or fallback."""
        cache_key = self._get_cache_key(finding_dict)
        cached_summary = self._load_from_cache(cache_key)
        if cached_summary:
            self._last_summary_source = "cache"
            return cached_summary, True, "cache"

        prepared = self._extract_reporter_evidence(finding_dict)
        user_prompt = SummaryPrompts.USER_PROMPT_TEMPLATE.format(
            title=prepared["title"],
            description=prepared["description"],
            cves=prepared["cves"],
            services=prepared["services"],
            ports=prepared["ports"],
        )
        user_prompt += f"\n\nHigh-Signal Evidence:\n{prepared['evidence_text']}\n"

        summary = None

        for attempt in range(ReporterConfig.RETRY_ATTEMPTS):
            try:
                response = self.client.models.generate_content(
                    model=ReporterConfig.GEMINI_MODEL,
                    contents=user_prompt,
                    config={
                        "system_instruction": SummaryPrompts.SYSTEM_PROMPT,
                        "temperature": ReporterConfig.SUMMARY_TEMPERATURE,
                        "top_p": ReporterConfig.SUMMARY_TOP_P,
                        "max_output_tokens": ReporterConfig.SUMMARY_MAX_TOKENS,
                    },
                )
                summary = self._sanitize_summary_text(response.text or "")
                if summary and not summary.endswith("."):
                    summary += "."
                break
            except Exception as exc:
                if attempt < ReporterConfig.RETRY_ATTEMPTS - 1:
                    print(
                        f"WARNING: attempt {attempt + 1} failed: {exc}. "
                        f"Retrying in {ReporterConfig.RETRY_DELAY_SECONDS}s..."
                    )
                    time.sleep(ReporterConfig.RETRY_DELAY_SECONDS)
                else:
                    print(f"ERROR: LLM request failed after retries: {exc}")
                    summary = None

        if not summary:
            fallback = self._build_fallback_summary(finding_dict)
            self._last_summary_source = "fallback"
            return fallback, False, "fallback"

        if not self._is_valid_summary(summary):
            fallback = self._build_fallback_summary(finding_dict)
            print(f"WARNING: summary failed validation, using fallback: {fallback}")
            self._last_summary_source = "fallback"
            return fallback, False, "fallback"

        self._save_to_cache(cache_key, summary)
        self._last_summary_source = "llm"
        return summary, False, "llm"

    def generate_summary(self, finding_dict: dict) -> tuple[str, bool]:
        """
        Generate a technical summary sentence for a single finding.

        Args:
            finding_dict: Dictionary with finding data

        Returns:
            Tuple of (technical summary sentence, cache_hit flag).
            On errors, falls back to a deterministic local summary.
        """
        summary, cache_hit, source = self._generate_summary_result(finding_dict)
        self._last_summary_source = source
        return summary, cache_hit

    def process_packet(self, packet_data: dict, max_findings: Optional[int] = None) -> dict:
        """
        Process a complete JSON packet, generating summaries for all findings.

        Args:
            packet_data: Ingested packet data as dictionary
            max_findings: Optional limit on number of findings to process

        Returns:
            Enhanced packet with summary in each finding's metadata
        """
        findings = packet_data.get("findings", [])

        if max_findings and len(findings) > max_findings:
            findings = findings[:max_findings]
            print(f"\nProcessing first {max_findings} findings (testing mode)...")
        else:
            print(f"\nProcessing packet with {len(findings)} findings...")

        for index, finding in enumerate(findings, 1):
            summary, is_cache_hit, summary_source = self._generate_summary_result(finding)

            if "metadata" not in finding:
                finding["metadata"] = {}

            finding["metadata"]["technical_summary"] = summary
            finding["metadata"]["summary_source"] = summary_source
            finding["metadata"]["summary_generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            finding["metadata"]["summary_prompt_version"] = ReporterConfig.SUMMARY_PROMPT_VERSION
            finding["metadata"]["summary_model"] = ReporterConfig.GEMINI_MODEL

            if index % 5 == 0 or index == 1:
                print(f"  OK {index}/{len(findings)} findings processed")

            if not is_cache_hit and index < len(findings):
                time.sleep(self.sleep_seconds_between_requests)

        self.report_count += len(findings)

        if "metadata" not in packet_data:
            packet_data["metadata"] = {}

        packet_data["metadata"]["reporter_stats"] = {
            "total_findings_summarized": len(findings),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "processing_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary_prompt_version": ReporterConfig.SUMMARY_PROMPT_VERSION,
            "summary_model": ReporterConfig.GEMINI_MODEL,
        }

        return packet_data

    def process_json_file(self, json_file_path: str | Path) -> Optional[dict]:
        """
        Process a JSON file from Section 1 output.

        Args:
            json_file_path: Path to JSON file

        Returns:
            Enriched packet data
        """
        json_file_path = Path(json_file_path)

        if not json_file_path.exists():
            print(f"ERROR: file not found: {json_file_path}")
            return None

        print(f"\nLoading JSON packet: {json_file_path.name}")

        try:
            with open(json_file_path, "r", encoding="utf-8") as handle:
                packet_data = json.load(handle)

            enriched_packet = self.process_packet(packet_data)
            print(f"Successfully processed {json_file_path.name}")
            return enriched_packet
        except Exception as exc:
            print(f"ERROR: processing JSON file failed: {exc}")
            return None

    def save_enriched_packet(self, packet_data: dict, output_dir: str | Path) -> Optional[Path]:
        """
        Save enriched packet with summaries.

        Args:
            packet_data: Enriched packet data
            output_dir: Directory to save to

        Returns:
            Path to saved file
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        source_file = packet_data.get("source_file", "unknown")
        clean_name = Path(source_file).stem
        output_file = output_dir / f"{clean_name}_enriched_{timestamp}.json"

        try:
            with open(output_file, "w", encoding="utf-8") as handle:
                json.dump(packet_data, handle, indent=2)
            print(f"Saved enriched packet to: {output_file.name}")
            return output_file
        except Exception as exc:
            print(f"ERROR: saving enriched packet failed: {exc}")
            return None

    def get_stats(self) -> dict:
        """Get processing statistics."""
        total = self.cache_hits + self.cache_misses
        return {
            "total_findings_processed": self.report_count,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": self.cache_hits / total if total > 0 else 0,
        }
