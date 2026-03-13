"""
LangExtract-based PDF Parser for vulnerability reports.

Uses Google's LangExtract library with Gemini for intelligent
extraction of security findings from unstructured PDF text.

This is an alternative to the regex-based pdf_parser.py.
Requires: GOOGLE_API_KEY environment variable to be set.

Reference: https://developers.googleblog.com/introducing-langextract-a-gemini-powered-information-extraction-library/
"""

import os
import re
from pathlib import Path
from typing import Optional

import fitz  # PyMuPDF for text extraction

from ..schemas import Finding, Severity, AffectedAsset, SourceType
from .base_parser import BaseParser


class PDFParserLangExtract(BaseParser):
    """
    LLM-powered PDF parser using Google's LangExtract.
    
    Benefits over regex-based parsing:
    - Understands context and semantics
    - Handles varied report formats (Nessus, Qualys, Rapid7, etc.)
    - Few-shot learning - adapts to new formats with examples
    - Source grounding - maps extractions to exact text locations
    
    Requires:
    - GOOGLE_API_KEY environment variable
    - langextract package: pip install langextract
    """
    
    PARSER_NAME = "pdf_parser_langextract"
    PARSER_VERSION = "2.0.0"
    SUPPORTED_EXTENSIONS = [".pdf"]
    SOURCE_TYPE = SourceType.VULNERABILITY_REPORT
    
    # Default model - can be overridden
    DEFAULT_MODEL = "gemini-2.5-flash"

    # LangExtract chunking / quality defaults tuned for vulnerability reports.
    # Smaller chunks prevent Gemini output-token truncation on large PDFs.
    DEFAULT_MAX_CHAR_BUFFER = 2000
    DEFAULT_EXTRACTION_PASSES = 2
    DEFAULT_MAX_WORKERS = 5
    
    def __init__(
        self, 
        file_path: str | Path,
        model_id: Optional[str] = None,
        api_key: Optional[str] = None,
        max_char_buffer: Optional[int] = None,
        extraction_passes: Optional[int] = None,
        max_workers: Optional[int] = None,
    ):
        super().__init__(file_path)
        self.model_id = model_id or self.DEFAULT_MODEL
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        self.max_char_buffer = max_char_buffer or self.DEFAULT_MAX_CHAR_BUFFER
        self.extraction_passes = extraction_passes or self.DEFAULT_EXTRACTION_PASSES
        self.max_workers = max_workers or self.DEFAULT_MAX_WORKERS
        self.full_text: str = ""
        self._langextract_available = self._check_langextract()
    
    def _check_langextract(self) -> bool:
        """Check if LangExtract is available."""
        try:
            import langextract
            return True
        except ImportError:
            self.add_warning(
                "LangExtract not installed. Install with: pip install langextract"
            )
            return False
    
    def _extract_text_from_pdf(self) -> str:
        """Extract all text from the PDF using PyMuPDF."""
        doc = fitz.open(self.file_path)
        text_parts = []
        
        for page_num, page in enumerate(doc):
            try:
                text_parts.append(page.get_text())
            except Exception as e:
                self.add_warning(f"Failed to extract text from page {page_num + 1}: {e}")
        
        doc.close()
        return "\n".join(text_parts)
    
    def _get_extraction_prompt(self) -> str:
        """Extraction prompt requesting all contract-required fields."""
        return """Extract all security vulnerabilities and findings from this penetration test or vulnerability assessment report.

For each finding, extract:
- severity: critical, high, medium, low, or informational
- title: the name of the vulnerability
- description: a concise description of the issue
- affected_hosts: IP addresses or hostnames affected
- hostnames: DNS / FQDN names if provided
- cve_ids: CVE identifiers (e.g. CVE-2024-1234)
- cvss_score: numeric CVSS score (0-10) if provided
- ports: affected ports with protocol (e.g. 22/TCP, 161/UDP)
- services: service names (e.g. SSH, HTTP, SNMP)
- remediation: recommended fix or mitigation

Use exact text from the document. Do not paraphrase.
Extract findings in order of appearance in the document."""
    
    def _get_few_shot_examples(self):
        """Few-shot examples spanning common report formats.

        Covers: generic pentest, OpenVAS/NVT, Nessus-style, and network
        service findings so that LangExtract generalises across vendors.
        """
        import langextract as lx

        return [
            lx.data.ExampleData(
                text="""CRITICAL - SQL Injection Vulnerability

Host: 192.168.1.50
CVSS Score: 9.8
CVE: CVE-2024-1234

The login form is vulnerable to SQL injection. Attacker can bypass authentication.
Recommendation: Implement parameterized queries.""",
                extractions=[
                    lx.data.Extraction(
                        extraction_class="vulnerability",
                        extraction_text="SQL Injection Vulnerability",
                        attributes={
                            "severity": "critical",
                            "title": "SQL Injection Vulnerability",
                            "description": "The login form is vulnerable to SQL injection",
                            "affected_hosts": ["192.168.1.50"],
                            "cve_ids": ["CVE-2024-1234"],
                            "cvss_score": 9.8,
                            "ports": ["443/TCP"],
                            "services": ["HTTPS"],
                            "remediation": "Implement parameterized queries",
                        },
                    )
                ],
            ),
            lx.data.ExampleData(
                text="""HIGH (CVSS: 7.5)
NVT: OpenSSH < 9.3p2 Remote Code Execution (OID: 1.3.6.1.4.1.25623.1.0.170001)
22/TCP (SSH)

Summary:
OpenSSH before 9.3p2 is vulnerable to CVE-2023-38408 enabling remote code
execution via forwarded ssh-agent.

Affected Hosts:
10.0.0.5, 10.0.0.12

Solution: Update OpenSSH to 9.3p2 or later.""",
                extractions=[
                    lx.data.Extraction(
                        extraction_class="vulnerability",
                        extraction_text="OpenSSH < 9.3p2 Remote Code Execution",
                        attributes={
                            "severity": "high",
                            "title": "OpenSSH < 9.3p2 Remote Code Execution",
                            "description": "OpenSSH before 9.3p2 is vulnerable to CVE-2023-38408 enabling remote code execution via forwarded ssh-agent",
                            "affected_hosts": ["10.0.0.5", "10.0.0.12"],
                            "cve_ids": ["CVE-2023-38408"],
                            "cvss_score": 7.5,
                            "ports": ["22/TCP"],
                            "services": ["SSH"],
                            "remediation": "Update OpenSSH to 9.3p2 or later",
                        },
                    )
                ],
            ),
            lx.data.ExampleData(
                text="""Plugin ID: 42263
Risk: Medium
Host: 10.10.1.100
Port: 161/UDP
Protocol: UDP

SNMP Agent Default Community Name (public)
The remote SNMP agent accepts the default 'public' community string.
An attacker may use this to gain read access to configuration data.

See Also: https://www.tenable.com/plugins/nessus/42263
Solution: Disable the SNMP service or filter incoming traffic.""",
                extractions=[
                    lx.data.Extraction(
                        extraction_class="vulnerability",
                        extraction_text="SNMP Agent Default Community Name (public)",
                        attributes={
                            "severity": "medium",
                            "title": "SNMP Agent Default Community Name (public)",
                            "description": "The remote SNMP agent accepts the default 'public' community string allowing unauthenticated read access to configuration data",
                            "affected_hosts": ["10.10.1.100"],
                            "cve_ids": [],
                            "cvss_score": None,
                            "ports": ["161/UDP"],
                            "services": ["SNMP"],
                            "remediation": "Disable the SNMP service or filter incoming traffic",
                        },
                    )
                ],
            ),
            lx.data.ExampleData(
                text="""LOW - SSL/TLS Certificate Expiry

Hostname: mail.corp.internal
IP: 172.16.5.20
Port: 443/TCP, 8443/TCP

The SSL certificate on the host expired on 2024-11-01.
Recommendation: Renew the SSL certificate.""",
                extractions=[
                    lx.data.Extraction(
                        extraction_class="vulnerability",
                        extraction_text="SSL/TLS Certificate Expiry",
                        attributes={
                            "severity": "low",
                            "title": "SSL/TLS Certificate Expiry",
                            "description": "The SSL certificate on the host expired on 2024-11-01",
                            "affected_hosts": ["172.16.5.20"],
                            "hostnames": ["mail.corp.internal"],
                            "cve_ids": [],
                            "cvss_score": None,
                            "ports": ["443/TCP", "8443/TCP"],
                            "services": ["HTTPS"],
                            "remediation": "Renew the SSL certificate",
                        },
                    )
                ],
            ),
        ]
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Convert string severity to enum."""
        if not severity_str:
            return Severity.UNKNOWN
        
        severity_lower = severity_str.lower().strip()
        
        if 'critical' in severity_lower:
            return Severity.CRITICAL
        elif 'high' in severity_lower:
            return Severity.HIGH
        elif 'medium' in severity_lower or 'moderate' in severity_lower:
            return Severity.MEDIUM
        elif 'low' in severity_lower:
            return Severity.LOW
        elif 'info' in severity_lower:
            return Severity.INFO
        
        return Severity.UNKNOWN
    
    @staticmethod
    def _coerce_string_list(value) -> list[str]:
        """Normalise an attribute that may be a string, list, or None."""
        if not value:
            return []
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        if isinstance(value, list):
            return [str(v).strip() for v in value if v]
        return []

    def _extraction_to_finding(self, extraction) -> Finding:
        """Convert a LangExtract extraction to our Finding schema."""
        attrs = extraction.attributes or {}

        affected_hosts = self._coerce_string_list(attrs.get("affected_hosts"))
        hostnames = self._coerce_string_list(attrs.get("hostnames"))

        affected_assets = [
            AffectedAsset(identifier=host, asset_type="host")
            for host in affected_hosts if host
        ]
        for hostname in hostnames:
            if hostname and hostname not in affected_hosts:
                affected_assets.append(
                    AffectedAsset(identifier=hostname, asset_type="host")
                )

        cve_ids = attrs.get("cve_ids", [])
        if isinstance(cve_ids, str):
            cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", cve_ids, re.IGNORECASE)
        cve_ids = [c for c in (cve_ids or []) if c]

        cvss_score = attrs.get("cvss_score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
                if not (0 <= cvss_score <= 10):
                    cvss_score = None
            except (ValueError, TypeError):
                cvss_score = None

        recommendations = []
        remediation = attrs.get("remediation", "")
        if remediation:
            recommendations.append(str(remediation))

        ports = self._coerce_string_list(attrs.get("ports"))
        services = self._coerce_string_list(attrs.get("services"))

        finding = Finding(
            severity=self._parse_severity(attrs.get("severity", "")),
            title=attrs.get("title", extraction.extraction_text)[:500],
            description=attrs.get("description", "")[:2000],
            affected_assets=affected_assets,
            raw_excerpt=extraction.extraction_text[:5000],
            cve_ids=cve_ids,
            cvss_score=cvss_score,
            recommendations=recommendations,
        )

        finding.metadata = {
            "ports": ports,
            "services": services,
            "hostnames": hostnames,
            "extracted_by_parser_version": self.PARSER_VERSION,
        }

        return finding
    
    def _fallback_to_regex_parser(self) -> list[Finding]:
        """Fall back to the regex-based PDFParser when LangExtract is
        unavailable or returns suspiciously few results."""
        try:
            from .pdf_parser import PDFParser
            regex_parser = PDFParser(self.file_path)
            results = regex_parser.parse()
            if results:
                self.add_warning(
                    f"Fell back to regex PDFParser: {len(results)} findings extracted."
                )
            return results
        except Exception as exc:
            self.add_warning(f"Regex fallback also failed: {exc}")
            return []

    def parse(self) -> list[Finding]:
        """Parse the PDF using LangExtract, with regex fallback."""
        findings: list[Finding] = []

        if not self._langextract_available:
            self.add_warning("LangExtract not installed -- falling back to regex parser.")
            return self._fallback_to_regex_parser()

        if not self.api_key:
            self.add_warning("GOOGLE_API_KEY not set -- falling back to regex parser.")
            return self._fallback_to_regex_parser()

        self.full_text = self._extract_text_from_pdf()

        if not self.full_text.strip():
            self.add_error("PDF appears to be empty or contains only images")
            return findings

        try:
            import langextract as lx

            if "LANGEXTRACT_API_KEY" not in os.environ:
                os.environ["LANGEXTRACT_API_KEY"] = self.api_key

            import warnings
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=FutureWarning)
                result = lx.extract(
                    text_or_documents=self.full_text,
                    prompt_description=self._get_extraction_prompt(),
                    examples=self._get_few_shot_examples(),
                    model_id=self.model_id,
                    max_char_buffer=self.max_char_buffer,
                    extraction_passes=self.extraction_passes,
                    max_workers=self.max_workers,
                )

            if hasattr(result, "extractions"):
                for extraction in result.extractions:
                    try:
                        findings.append(self._extraction_to_finding(extraction))
                    except Exception as e:
                        self.add_warning(f"Failed to convert extraction: {e}")
            elif hasattr(result, "__iter__"):
                for doc_result in result:
                    if hasattr(doc_result, "extractions"):
                        for extraction in doc_result.extractions:
                            try:
                                findings.append(self._extraction_to_finding(extraction))
                            except Exception as e:
                                self.add_warning(f"Failed to convert extraction: {e}")

        except Exception as e:
            self.add_error(f"LangExtract extraction failed: {e}")

        if not findings:
            self.add_warning("LangExtract returned 0 findings -- trying regex fallback.")
            findings = self._fallback_to_regex_parser()

        return findings
    
    def extract_document_summary(self) -> Optional[str]:
        """Extract summary - LangExtract doesn't provide this directly."""
        if not self.full_text:
            return None
        
        # Return first substantial paragraph as summary
        paragraphs = self.full_text.split('\n\n')
        for para in paragraphs:
            para = para.strip()
            if len(para) > 100:
                return para[:1000]
        
        return None
