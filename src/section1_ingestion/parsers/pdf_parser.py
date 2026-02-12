"""
PDF Parser for vulnerability reports and security assessments.

Uses PyMuPDF (fitz) for text extraction and attempts to identify
security findings within the document structure.
"""

import re
from pathlib import Path
from typing import Optional

import fitz  # PyMuPDF

from ..schemas import Finding, Severity, AffectedAsset, SourceType
from .base_parser import BaseParser


class PDFParser(BaseParser):
    """
    Parser for PDF vulnerability reports.
    
    Extracts security findings by analyzing document structure,
    looking for common patterns in vulnerability reports such as:
    - Severity indicators (Critical, High, Medium, Low)
    - CVE references
    - IP addresses and hostnames
    - Finding sections with titles and descriptions
    """
    
    PARSER_NAME = "pdf_parser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_EXTENSIONS = [".pdf"]
    SOURCE_TYPE = SourceType.VULNERABILITY_REPORT
    
    # Regex patterns for extraction
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    CVSS_PATTERN = re.compile(r'CVSS[:\s]*(\d+\.?\d*)', re.IGNORECASE)
    
    # Severity keywords to look for
    SEVERITY_KEYWORDS = {
        Severity.CRITICAL: ['critical', 'severity: critical', 'risk: critical'],
        Severity.HIGH: ['high', 'severity: high', 'risk: high'],
        Severity.MEDIUM: ['medium', 'moderate', 'severity: medium', 'risk: medium'],
        Severity.LOW: ['low', 'severity: low', 'risk: low'],
        Severity.INFO: ['info', 'informational', 'severity: info'],
    }
    
    def __init__(self, file_path: str | Path):
        super().__init__(file_path)
        self.doc: Optional[fitz.Document] = None
        self.full_text: str = ""
    
    def _extract_full_text(self) -> str:
        """Extract all text from the PDF."""
        self.doc = fitz.open(self.file_path)
        text_parts = []
        
        for page_num, page in enumerate(self.doc):
            try:
                text_parts.append(page.get_text())
            except Exception as e:
                self.add_warning(f"Failed to extract text from page {page_num + 1}: {e}")
        
        return "\n".join(text_parts)
    
    def _detect_severity(self, text: str) -> Severity:
        """Detect severity level from text content."""
        text_lower = text.lower()
        
        for severity, keywords in self.SEVERITY_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text_lower:
                    return severity
        
        return Severity.UNKNOWN
    
    def _extract_cves(self, text: str) -> list[str]:
        """Extract all CVE IDs from text."""
        return list(set(self.CVE_PATTERN.findall(text)))
    
    def _extract_ips(self, text: str) -> list[str]:
        """Extract all IP addresses from text."""
        return list(set(self.IP_PATTERN.findall(text)))
    
    def _extract_cvss(self, text: str) -> Optional[float]:
        """Extract CVSS score from text."""
        match = self.CVSS_PATTERN.search(text)
        if match:
            try:
                score = float(match.group(1))
                if 0 <= score <= 10:
                    return score
            except ValueError:
                pass
        return None
    
    def _split_into_sections(self, text: str) -> list[dict]:
        """
        Attempt to split document into finding sections.
        
        This is a heuristic approach that looks for common patterns
        in vulnerability reports. May need customization for specific
        report formats (Nessus, Qualys, Rapid7, etc.).
        """
        sections = []
        
        # Common section header patterns
        # Pattern 1: Numbered findings (1. Finding Title, 2. Finding Title)
        # Pattern 2: Severity headers (CRITICAL: Finding, HIGH: Finding)
        # Pattern 3: Finding ID patterns (VULN-001, Finding 1, etc.)
        
        # Simple approach: split on severity keywords followed by colons
        severity_split_pattern = re.compile(
            r'\n\s*((?:CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)[:\s]+[^\n]+)',
            re.IGNORECASE
        )
        
        matches = list(severity_split_pattern.finditer(text))
        
        if matches:
            for i, match in enumerate(matches):
                start = match.start()
                end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
                section_text = text[start:end].strip()
                
                # Extract title from the first line
                first_line = section_text.split('\n')[0].strip()
                
                sections.append({
                    'title': first_line[:200],  # Limit title length
                    'content': section_text,
                })
        
        # If no sections found, treat entire document as one finding
        if not sections:
            self.add_warning("Could not identify individual findings; treating document as single finding")
            sections.append({
                'title': f"Findings from {self.file_path.name}",
                'content': text,
            })
        
        return sections
    
    def parse(self) -> list[Finding]:
        """Parse the PDF and extract security findings."""
        findings = []
        
        # Extract full text
        self.full_text = self._extract_full_text()
        
        if not self.full_text.strip():
            self.add_error("PDF appears to be empty or contains only images")
            return findings
        
        # Split into sections
        sections = self._split_into_sections(self.full_text)
        
        for section in sections:
            title = section['title']
            content = section['content']
            
            # Extract metadata from section
            severity = self._detect_severity(content)
            cves = self._extract_cves(content)
            ips = self._extract_ips(content)
            cvss = self._extract_cvss(content)
            
            # Build affected assets from IPs
            affected_assets = [
                AffectedAsset(identifier=ip, asset_type="host")
                for ip in ips[:20]  # Limit to 20 assets per finding
            ]
            
            # Create finding
            finding = Finding(
                severity=severity,
                title=title,
                description=content[:2000],  # Limit description length
                affected_assets=affected_assets,
                raw_excerpt=content[:5000],  # Keep more for raw excerpt
                cve_ids=cves,
                cvss_score=cvss,
            )
            
            findings.append(finding)
        
        return findings
    
    def extract_document_summary(self) -> Optional[str]:
        """
        Extract executive summary from the PDF.
        
        Looks for common summary section headers.
        """
        if not self.full_text:
            return None
        
        # Look for executive summary section
        summary_patterns = [
            r'executive\s+summary[:\s]*\n(.*?)(?=\n\s*\n|\Z)',
            r'summary[:\s]*\n(.*?)(?=\n\s*\n|\Z)',
            r'overview[:\s]*\n(.*?)(?=\n\s*\n|\Z)',
        ]
        
        for pattern in summary_patterns:
            match = re.search(pattern, self.full_text, re.IGNORECASE | re.DOTALL)
            if match:
                summary = match.group(1).strip()
                if len(summary) > 50:  # Ensure it's substantial
                    return summary[:1000]  # Limit length
        
        # Fallback: return first paragraph
        paragraphs = self.full_text.split('\n\n')
        for para in paragraphs:
            para = para.strip()
            if len(para) > 100:
                return para[:1000]
        
        return None
    
    def __del__(self):
        """Clean up PDF document."""
        if hasattr(self, 'doc') and self.doc:
            self.doc.close()
