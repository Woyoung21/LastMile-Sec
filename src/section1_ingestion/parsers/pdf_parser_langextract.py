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
    PARSER_VERSION = "1.0.0"
    SUPPORTED_EXTENSIONS = [".pdf"]
    SOURCE_TYPE = SourceType.VULNERABILITY_REPORT
    
    # Default model - can be overridden
    DEFAULT_MODEL = "gemini-2.0-flash"
    
    def __init__(
        self, 
        file_path: str | Path,
        model_id: Optional[str] = None,
        api_key: Optional[str] = None
    ):
        super().__init__(file_path)
        self.model_id = model_id or self.DEFAULT_MODEL
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
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
        """Get the prompt for LangExtract."""
        return """Extract all security vulnerabilities and findings from this penetration test or vulnerability assessment report.

For each finding, extract:
- The severity level (critical, high, medium, low, or informational)
- The title or name of the vulnerability
- A description of the issue
- Any affected hosts, IP addresses, or assets
- CVE identifiers if mentioned
- CVSS scores if provided
- Recommended remediation steps if included

Use exact text from the document for extractions. Do not paraphrase.
Extract findings in order of appearance in the document."""
    
    def _get_few_shot_examples(self):
        """
        Get few-shot examples for LangExtract.
        
        These examples teach the model what to extract and how to structure it.
        """
        import langextract as lx
        
        return [
            # Example 1: Critical finding with CVE
            lx.data.ExampleData(
                text="""CRITICAL - SQL Injection in Authentication Module
                
Host: 192.168.1.50 (web-server-01)
CVSS Score: 9.8
CVE: CVE-2024-1234

Description: The login form at /api/auth/login is vulnerable to SQL injection attacks. 
An attacker can bypass authentication by injecting malicious SQL code into the username parameter.

Evidence: Parameter 'username' accepts: ' OR '1'='1' --

Recommendation: Implement parameterized queries and input validation. Update to the latest 
version of the authentication library.""",
                extractions=[
                    lx.data.Extraction(
                        extraction_class="vulnerability",
                        extraction_text="SQL Injection in Authentication Module",
                        attributes={
                            "severity": "critical",
                            "title": "SQL Injection in Authentication Module",
                            "description": "The login form at /api/auth/login is vulnerable to SQL injection attacks. An attacker can bypass authentication by injecting malicious SQL code into the username parameter.",
                            "affected_hosts": ["192.168.1.50", "web-server-01"],
                            "cve_ids": ["CVE-2024-1234"],
                            "cvss_score": 9.8,
                            "remediation": "Implement parameterized queries and input validation. Update to the latest version of the authentication library."
                        }
                    )
                ]
            ),
            # Example 2: Medium finding without CVE
            lx.data.ExampleData(
                text="""MEDIUM - Missing Security Headers

Affected Systems: 10.0.0.5, 10.0.0.6, 10.0.0.7
CVSS: 5.3

The web application does not implement recommended security headers including:
- X-Content-Type-Options
- X-Frame-Options  
- Content-Security-Policy

This could allow clickjacking attacks and MIME type sniffing.

Remediation: Configure the web server to return appropriate security headers on all responses.""",
                extractions=[
                    lx.data.Extraction(
                        extraction_class="vulnerability",
                        extraction_text="Missing Security Headers",
                        attributes={
                            "severity": "medium",
                            "title": "Missing Security Headers",
                            "description": "The web application does not implement recommended security headers including: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy. This could allow clickjacking attacks and MIME type sniffing.",
                            "affected_hosts": ["10.0.0.5", "10.0.0.6", "10.0.0.7"],
                            "cve_ids": [],
                            "cvss_score": 5.3,
                            "remediation": "Configure the web server to return appropriate security headers on all responses."
                        }
                    )
                ]
            ),
            # Example 3: Low/Info finding
            lx.data.ExampleData(
                text="""LOW - Server Version Disclosure

Target: 172.16.0.100
Risk: Low

The server reveals its version information in HTTP response headers:
Server: Apache/2.4.41 (Ubuntu)

This information could assist attackers in identifying known vulnerabilities.

Fix: Configure the server to suppress version information in responses.""",
                extractions=[
                    lx.data.Extraction(
                        extraction_class="vulnerability",
                        extraction_text="Server Version Disclosure",
                        attributes={
                            "severity": "low",
                            "title": "Server Version Disclosure",
                            "description": "The server reveals its version information in HTTP response headers: Server: Apache/2.4.41 (Ubuntu). This information could assist attackers in identifying known vulnerabilities.",
                            "affected_hosts": ["172.16.0.100"],
                            "cve_ids": [],
                            "cvss_score": None,
                            "remediation": "Configure the server to suppress version information in responses."
                        }
                    )
                ]
            )
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
    
    def _extraction_to_finding(self, extraction) -> Finding:
        """Convert a LangExtract extraction to our Finding schema."""
        attrs = extraction.attributes or {}
        
        # Parse affected hosts
        affected_hosts = attrs.get('affected_hosts', [])
        if isinstance(affected_hosts, str):
            # Handle comma-separated string
            affected_hosts = [h.strip() for h in affected_hosts.split(',')]
        
        affected_assets = [
            AffectedAsset(identifier=host, asset_type="host")
            for host in affected_hosts if host
        ]
        
        # Parse CVE IDs
        cve_ids = attrs.get('cve_ids', [])
        if isinstance(cve_ids, str):
            # Extract CVE patterns from string
            cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', cve_ids, re.IGNORECASE)
        
        # Parse CVSS score
        cvss_score = attrs.get('cvss_score')
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
                if not (0 <= cvss_score <= 10):
                    cvss_score = None
            except (ValueError, TypeError):
                cvss_score = None
        
        # Parse remediation as recommendations
        recommendations = []
        remediation = attrs.get('remediation', '')
        if remediation:
            recommendations.append(str(remediation))
        
        return Finding(
            severity=self._parse_severity(attrs.get('severity', '')),
            title=attrs.get('title', extraction.extraction_text)[:500],
            description=attrs.get('description', '')[:2000],
            affected_assets=affected_assets,
            raw_excerpt=extraction.extraction_text[:5000],
            cve_ids=cve_ids,
            cvss_score=cvss_score,
            recommendations=recommendations,
        )
    
    def parse(self) -> list[Finding]:
        """Parse the PDF using LangExtract."""
        findings = []
        
        # Check prerequisites
        if not self._langextract_available:
            self.add_error("LangExtract not available. Falling back would require regex parser.")
            return findings
        
        if not self.api_key:
            self.add_error(
                "GOOGLE_API_KEY not set. Set environment variable or pass api_key parameter."
            )
            return findings
        
        # Extract text from PDF
        self.full_text = self._extract_text_from_pdf()
        
        if not self.full_text.strip():
            self.add_error("PDF appears to be empty or contains only images")
            return findings
        
        try:
            import langextract as lx
            
            # Configure API key
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            
            # Run extraction
            result = lx.extract(
                text_or_documents=self.full_text,
                prompt_description=self._get_extraction_prompt(),
                examples=self._get_few_shot_examples(),
                model_id=self.model_id,
            )
            
            # Convert extractions to findings
            if hasattr(result, 'extractions'):
                for extraction in result.extractions:
                    try:
                        finding = self._extraction_to_finding(extraction)
                        findings.append(finding)
                    except Exception as e:
                        self.add_warning(f"Failed to convert extraction: {e}")
            
            # Also check if result is iterable of documents
            elif hasattr(result, '__iter__'):
                for doc_result in result:
                    if hasattr(doc_result, 'extractions'):
                        for extraction in doc_result.extractions:
                            try:
                                finding = self._extraction_to_finding(extraction)
                                findings.append(finding)
                            except Exception as e:
                                self.add_warning(f"Failed to convert extraction: {e}")
            
            if not findings:
                self.add_warning("LangExtract found no vulnerabilities in the document")
        
        except Exception as e:
            self.add_error(f"LangExtract extraction failed: {e}")
        
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
