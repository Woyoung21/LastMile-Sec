"""
CSV Parser for security logs and vulnerability data.

Handles CSV files from various sources including:
- Security scanner exports
- SIEM log exports
- Firewall/IDS logs
- Custom security tooling output
"""

import re
from pathlib import Path
from typing import Optional
from datetime import datetime

import pandas as pd

from ..schemas import Finding, Severity, AffectedAsset, SourceType
from .base_parser import BaseParser


class CSVParser(BaseParser):
    """
    Parser for CSV security logs and vulnerability data.
    
    Similar to ExcelParser but optimized for CSV files.
    Also handles log-style CSVs with timestamp-based events.
    """
    
    PARSER_NAME = "csv_parser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_EXTENSIONS = [".csv"]
    SOURCE_TYPE = SourceType.CSV_LOG
    
    # Column name variations (same as Excel parser)
    COLUMN_MAPPINGS = {
        'title': ['vulnerability', 'vuln', 'finding', 'title', 'name', 'issue', 'event', 'alert', 'message', 'msg'],
        'description': ['description', 'desc', 'details', 'synopsis', 'summary', 'info'],
        'severity': ['severity', 'risk', 'risk level', 'criticality', 'priority', 'level'],
        'cvss': ['cvss', 'cvss score', 'cvss v3', 'cvss v2', 'score'],
        'cve': ['cve', 'cve id', 'cve-id', 'cves'],
        'host': ['host', 'ip', 'ip address', 'target', 'asset', 'hostname', 'src_ip', 'dst_ip', 'source', 'destination'],
        'source_ip': ['src_ip', 'source_ip', 'srcip', 'source', 'src'],
        'dest_ip': ['dst_ip', 'dest_ip', 'dstip', 'destination', 'dst', 'dest'],
        'port': ['port', 'service port', 'dst_port', 'src_port', 'dport', 'sport'],
        'protocol': ['protocol', 'proto'],
        'timestamp': ['timestamp', 'time', 'date', 'datetime', 'event_time', 'log_time', '@timestamp'],
        'action': ['action', 'result', 'status', 'disposition'],
    }
    
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    
    def __init__(self, file_path: str | Path, delimiter: str = ",", encoding: str = "utf-8"):
        super().__init__(file_path)
        self.delimiter = delimiter
        self.encoding = encoding
        self.df: Optional[pd.DataFrame] = None
        self.column_map: dict[str, str] = {}
        self.is_log_format = False
    
    def _normalize_column_name(self, col: str) -> str:
        """Normalize column name for matching."""
        return col.lower().strip().replace('_', ' ').replace('-', ' ')
    
    def _detect_column_mapping(self, df: pd.DataFrame) -> dict[str, str]:
        """Auto-detect column mappings."""
        column_map = {}
        df_columns = {self._normalize_column_name(c): c for c in df.columns}
        
        for our_field, variations in self.COLUMN_MAPPINGS.items():
            for variation in variations:
                if variation in df_columns:
                    column_map[our_field] = df_columns[variation]
                    break
        
        return column_map
    
    def _detect_log_format(self) -> bool:
        """Detect if this CSV is a log file (has timestamps and events)."""
        return 'timestamp' in self.column_map and ('title' in self.column_map or 'source_ip' in self.column_map)
    
    def _parse_severity(self, value) -> Severity:
        """Convert severity representations to our enum."""
        if pd.isna(value):
            return Severity.UNKNOWN
        
        value_str = str(value).lower().strip()
        
        try:
            score = float(value_str)
            if score >= 9.0:
                return Severity.CRITICAL
            elif score >= 7.0:
                return Severity.HIGH
            elif score >= 4.0:
                return Severity.MEDIUM
            elif score >= 0.1:
                return Severity.LOW
            else:
                return Severity.INFO
        except ValueError:
            pass
        
        if 'critical' in value_str or 'emergency' in value_str or 'alert' in value_str:
            return Severity.CRITICAL
        elif 'high' in value_str or 'error' in value_str:
            return Severity.HIGH
        elif 'medium' in value_str or 'warning' in value_str or 'warn' in value_str:
            return Severity.MEDIUM
        elif 'low' in value_str or 'notice' in value_str:
            return Severity.LOW
        elif 'info' in value_str or 'debug' in value_str:
            return Severity.INFO
        
        return Severity.UNKNOWN
    
    def _parse_timestamp(self, value) -> Optional[datetime]:
        """Parse timestamp from various formats."""
        if pd.isna(value):
            return None
        
        # If it's already a datetime
        if isinstance(value, datetime):
            return value
        
        # Try pandas datetime parsing
        try:
            return pd.to_datetime(value).to_pydatetime()
        except Exception:
            pass
        
        return None
    
    def _safe_str(self, value, default: str = "") -> str:
        """Safely convert value to string."""
        if pd.isna(value):
            return default
        return str(value).strip()
    
    def _safe_float(self, value) -> Optional[float]:
        """Safely convert value to float."""
        if pd.isna(value):
            return None
        try:
            score = float(value)
            return score if 0 <= score <= 10 else None
        except (ValueError, TypeError):
            return None
    
    def _extract_cves(self, value) -> list[str]:
        """Extract CVE IDs from a cell value."""
        if pd.isna(value):
            return []
        return list(set(self.CVE_PATTERN.findall(str(value))))
    
    def parse(self) -> list[Finding]:
        """Parse the CSV file and extract security findings."""
        findings = []
        
        try:
            # Try different encodings if the default fails
            encodings_to_try = [self.encoding, 'utf-8', 'latin-1', 'cp1252']
            
            for enc in encodings_to_try:
                try:
                    self.df = pd.read_csv(
                        self.file_path,
                        delimiter=self.delimiter,
                        encoding=enc,
                        on_bad_lines='warn'
                    )
                    break
                except UnicodeDecodeError:
                    continue
            else:
                self.add_error("Could not decode CSV file with any supported encoding")
                return findings
            
            if self.df.empty:
                self.add_warning("CSV file is empty")
                return findings
            
            # Detect column mapping
            self.column_map = self._detect_column_mapping(self.df)
            self.is_log_format = self._detect_log_format()
            
            # Process each row
            for idx, row in self.df.iterrows():
                try:
                    # Build title
                    title = ""
                    if 'title' in self.column_map:
                        title = self._safe_str(row.get(self.column_map['title']))
                    
                    if not title and self.is_log_format:
                        # For logs, construct title from available fields
                        parts = []
                        if 'source_ip' in self.column_map:
                            parts.append(f"From: {self._safe_str(row.get(self.column_map['source_ip']))}")
                        if 'dest_ip' in self.column_map:
                            parts.append(f"To: {self._safe_str(row.get(self.column_map['dest_ip']))}")
                        if 'action' in self.column_map:
                            parts.append(f"Action: {self._safe_str(row.get(self.column_map['action']))}")
                        title = " | ".join(parts) if parts else f"Event {idx + 1}"
                    
                    if not title:
                        title = f"Entry {idx + 1}"
                    
                    # Build description
                    description = ""
                    if 'description' in self.column_map:
                        description = self._safe_str(row.get(self.column_map['description']))
                    
                    if not description:
                        # Use all non-empty fields as description
                        description = " | ".join(
                            f"{col}: {self._safe_str(val)}"
                            for col, val in row.items()
                            if not pd.isna(val) and col != self.column_map.get('title')
                        )
                    
                    # Skip empty rows
                    if not title and not description:
                        continue
                    
                    # Extract severity
                    severity = Severity.UNKNOWN
                    if 'severity' in self.column_map:
                        severity = self._parse_severity(row.get(self.column_map['severity']))
                    
                    # Extract CVEs
                    cves = self._extract_cves(description)
                    if 'cve' in self.column_map:
                        cves.extend(self._extract_cves(row.get(self.column_map['cve'])))
                    cves = list(set(cves))
                    
                    # Extract CVSS
                    cvss = None
                    if 'cvss' in self.column_map:
                        cvss = self._safe_float(row.get(self.column_map['cvss']))
                    
                    # Build affected assets
                    affected_assets = []
                    for field in ['host', 'source_ip', 'dest_ip']:
                        if field in self.column_map:
                            value = self._safe_str(row.get(self.column_map[field]))
                            if value and value not in [a.identifier for a in affected_assets]:
                                affected_assets.append(AffectedAsset(
                                    identifier=value,
                                    asset_type="host"
                                ))
                    
                    # Extract network details for log format
                    source_ip = None
                    dest_ip = None
                    protocol = None
                    timestamp_observed = None
                    
                    if self.is_log_format:
                        if 'source_ip' in self.column_map:
                            source_ip = self._safe_str(row.get(self.column_map['source_ip'])) or None
                        if 'dest_ip' in self.column_map:
                            dest_ip = self._safe_str(row.get(self.column_map['dest_ip'])) or None
                        if 'protocol' in self.column_map:
                            protocol = self._safe_str(row.get(self.column_map['protocol'])) or None
                        if 'timestamp' in self.column_map:
                            timestamp_observed = self._parse_timestamp(row.get(self.column_map['timestamp']))
                    
                    # Build raw excerpt
                    raw_excerpt = " | ".join(
                        f"{col}: {self._safe_str(val)}"
                        for col, val in row.items()
                        if not pd.isna(val)
                    )
                    
                    finding = Finding(
                        severity=severity,
                        title=title[:500],
                        description=description[:2000],
                        affected_assets=affected_assets,
                        raw_excerpt=raw_excerpt[:5000],
                        cve_ids=cves,
                        cvss_score=cvss,
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        protocol=protocol,
                        timestamp_observed=timestamp_observed,
                    )
                    
                    findings.append(finding)
                    
                except Exception as e:
                    self.add_error(f"Error parsing row {idx}: {e}")
            
        except Exception as e:
            self.add_error(f"Error reading CSV file: {e}")
        
        return findings
    
    def extract_document_summary(self) -> Optional[str]:
        """Generate summary from parsed data."""
        if self.df is None:
            return None
        
        return f"CSV file with {len(self.df)} rows and {len(self.df.columns)} columns. Columns: {', '.join(self.df.columns[:10])}{'...' if len(self.df.columns) > 10 else ''}"
