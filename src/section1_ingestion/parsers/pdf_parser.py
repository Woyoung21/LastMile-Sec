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
    # CVSS pattern: must have word boundary before CVSS and valid score 0-10
    CVSS_PATTERN = re.compile(r'(?:^|\s|\()CVSS[:\s]*([0-9](?:\.[0-9])?|10(?:\.0)?)(?:\s|$|\))', re.IGNORECASE | re.MULTILINE)
    # OID pattern for OpenVAS NVT format
    OID_PATTERN = re.compile(r'OID:\s*(1\.3\.6\.1\.4\.1\.25623(?:\.\d+)*)', re.IGNORECASE)
    # NVT title extraction: "NVT: [Title] (OID: ...)" format
    NVT_PATTERN = re.compile(r'NVT:\s*([^(]+?)\s*\(OID:', re.IGNORECASE)
    
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
        """Extract all IP addresses from text, excluding OID components."""
        ips = self.IP_PATTERN.findall(text)
        # Filter out OID components (1.3.6.x patterns are OIDs, not IPs)
        filtered = []
        for ip in ips:
            parts = ip.split('.')
            # OID prefixes: 1.3.6.1, 1.2.3, etc. Real IPs don't start with 1, 0, or high numbers like 255
            first_octet = int(parts[0])
            if 2 <= first_octet <= 254:  # Valid IP address first octet range
                # Also skip common OID patterns (1.3.6.x.x.x...)
                if not (parts[0] == '1' and len(parts) > 2 and parts[1] == '3'):
                    filtered.append(ip)
        return list(dict.fromkeys(filtered))  # Remove duplicates while preserving order
    
    def _extract_cvss(self, text: str) -> Optional[float]:
        """Extract CVSS score from text, with stricter pattern matching."""
        match = self.CVSS_PATTERN.search(text)
        if match:
            try:
                score = float(match.group(1))
                # Valid CVSS scores are between 0 and 10
                if 0 <= score <= 10:
                    return score
            except (ValueError, IndexError):
                pass
        return None
    
    def _extract_nvt_oid(self, text: str) -> Optional[str]:
        """Extract NVT OID from vulnerability entry (OpenVAS format)."""
        match = self.OID_PATTERN.search(text)
        if match:
            return match.group(1)
        return None
    
    def _extract_nvt_title(self, text: str) -> Optional[str]:
        """Extract NVT title from 'NVT: [Title] (OID: ...)' format."""
        match = self.NVT_PATTERN.search(text)
        if match:
            return match.group(1).strip()
        return None
    
    def _extract_ports(self, text: str) -> list[str]:
        """Extract listening ports and services from text."""
        ports = []
        
        # Match patterns like "22/TCP", "443/TCP", "22 (SSH)", "Port 22", etc.
        # OpenVAS format: "22/TCP (SSH), 830/TCP, 443"
        # Focus on most reliable patterns to avoid false positives
        port_patterns = [
            r'(\d+)/(?:TCP|UDP)',  # 22/TCP, 443/UDP format - most reliable
        ]
        
        for pattern in port_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            ports.extend(matches)
        
        # Filter to valid port numbers (1-65535)
        valid_ports = []
        for port in ports:
            try:
                port_num = int(port)
                if 1 <= port_num <= 65535:
                    valid_ports.append(port)
            except ValueError:
                pass
        
        return list(dict.fromkeys(valid_ports))  # Remove duplicates while preserving order
    
    def _extract_services(self, text: str) -> list[str]:
        """Extract service names mentioned in the finding."""
        services = []
        service_keywords = ['ssh', 'http', 'https', 'ftp', 'smtp', 'snmp', 'dns', 'ldap', 'kerberos', 'ntp', 'telnet']
        
        text_lower = text.lower()
        for service in service_keywords:
            if service in text_lower:
                services.append(service.upper())
        
        # Also look for services in parentheses like (SSH), (HTTP), etc.
        service_pattern = r'\(([A-Z]{2,10})\)'
        matches = re.findall(service_pattern, text)
        for match in matches:
            if match.upper() in ['SSH', 'HTTP', 'HTTPS', 'FTP', 'SMTP', 'SNMP', 'DNS', 'LDAP', 'KERBEROS', 'NTP', 'TELNET']:
                services.append(match.upper())
        
        return list(dict.fromkeys(services))  # Remove duplicates
    
    def _extract_hostnames(self, text: str) -> list[str]:
        """Extract hostnames from affected assets, filtering false positives."""
        hostnames = []
        # Match domain names with internal TLDs only (local, internal, corp, lan, etc.)
        hostname_pattern = r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:local|internal|corp|lan|windsor)\b'
        matches = re.findall(hostname_pattern, text.lower())
        hostnames.extend(matches)
        
        return list(dict.fromkeys(hostnames))  # Remove duplicates while preserving order
    
    def _split_into_sections(self, text: str) -> list[dict]:
        """
        Split document into finding sections using OpenVAS format patterns.
        
        Format:
        SEVERITY (CVSS: X.X)
        NVT: TITLE [Additional Info] (OID: 1.3.6.1.4.1.25623.1.0.XXXXX)
        Ports/Services
        
        Summary/Description follows...
        """
        sections = []
        
        # Pattern to match OpenVAS/Qualys style findings:
        # SEVERITY (CVSS: X.X) on its own line
        # followed by NVT: title (OID: ...) 
        # Pattern is more restrictive to avoid matching table headers
        finding_pattern = re.compile(
            r'((?:CRITICAL|HIGH|MEDIUM|LOW)\s+\(CVSS:\s*[\d.]+\))\s*\n\s*(NVT:[^\n]+)\s*\n([^\n]*)',
            re.IGNORECASE | re.MULTILINE
        )
        
        matches = list(finding_pattern.finditer(text))
        
        if matches:
            for i, match in enumerate(matches):
                start = match.start()
                end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
                section_text = text[start:end].strip()
                
                # Extract first line as title (from NVT line)
                ntv_line = match.group(2)
                first_line = match.group(1) + "\n" + ntv_line
                
                sections.append({
                    'title': first_line[:300],  # Increased from 200
                    'content': section_text,
                })
        else:
            # Fallback: use original pattern if OpenVAS pattern doesn't match
            severity_split_pattern = re.compile(
                r'\n\s*((?:CRITICAL|HIGH|MEDIUM|LOW)[:\s]+[^\n]+)',
                re.IGNORECASE
            )
            
            matches = list(severity_split_pattern.finditer(text))
            
            if matches:
                for i, match in enumerate(matches):
                    start = match.start()
                    end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
                    section_text = text[start:end].strip()
                    first_line = section_text.split('\n')[0].strip()
                    
                    sections.append({
                        'title': first_line[:200],
                        'content': section_text,
                    })
        
        # If still no sections found, treat entire document as one finding
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
            nvt_oid = self._extract_nvt_oid(content)
            nvt_title = self._extract_nvt_title(content)
            ports = self._extract_ports(content)
            services = self._extract_services(content)
            hostnames = self._extract_hostnames(content)
            
            # Build affected assets from IPs and hostnames
            affected_assets = []
            
            # Add IP-based assets
            for ip in ips[:20]:  # Limit to 20 assets per finding
                affected_assets.append(
                    AffectedAsset(identifier=ip, asset_type="host")
                )
            
            # Add hostname-based assets
            for hostname in hostnames[:10]:
                affected_assets.append(
                    AffectedAsset(identifier=hostname, asset_type="host")
                )
            
            # Create finding with enriched data
            # Use NVT title if available, otherwise use parsed title
            finding_title = nvt_title if nvt_title else title
            
            finding = Finding(
                severity=severity,
                title=finding_title,
                description=content[:2000],  # Limit description length
                affected_assets=affected_assets,
                raw_excerpt=content[:5000],  # Keep more for raw excerpt
                cve_ids=cves,
                cvss_score=cvss,
            )
            
            # Store additional metadata in the object
            # These provide enriched data for analysis and reporting
            finding.metadata = {
                'nvt_oid': nvt_oid,
                'nvt_title': nvt_title,
                'ports': ports,
                'services': services,
                'hostnames': hostnames,
                'extracted_by_parser_version': self.PARSER_VERSION,
            }
            
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
