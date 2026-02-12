"""
Pydantic schemas for Section 1: Ingestion Pipeline

These models define the structure of normalized JSON packets
that will be passed to Section 2 (Reporter & Mapper).
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from uuid import uuid4


class SourceType(str, Enum):
    """Type of source document that was ingested."""
    VULNERABILITY_REPORT = "vulnerability_report"
    PCAP = "pcap"
    CSV_LOG = "csv_log"
    EXCEL = "excel"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Severity level of a security finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class AffectedAsset(BaseModel):
    """An asset affected by a security finding."""
    identifier: str = Field(..., description="IP address, hostname, or asset ID")
    asset_type: Optional[str] = Field(None, description="Type of asset (server, endpoint, network device, etc.)")
    details: Optional[str] = Field(None, description="Additional context about the asset")


class Finding(BaseModel):
    """
    A single security finding extracted from a source document.
    
    This is the core unit of data that flows through the pipeline.
    Each finding represents one vulnerability, event, or issue.
    """
    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique identifier for this finding")
    
    # Classification
    severity: Severity = Field(default=Severity.UNKNOWN, description="Severity level")
    title: str = Field(..., description="Brief title of the finding")
    description: str = Field(..., description="Detailed description of the finding")
    
    # Technical details
    affected_assets: list[AffectedAsset] = Field(default_factory=list, description="Assets affected by this finding")
    raw_excerpt: str = Field(default="", description="Original text excerpt from source document")
    
    # CVE/CVSS information (if available)
    cve_ids: list[str] = Field(default_factory=list, description="Associated CVE identifiers")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score if available")
    
    # Additional context
    recommendations: list[str] = Field(default_factory=list, description="Any recommendations from the source")
    references: list[str] = Field(default_factory=list, description="Reference URLs or documentation")
    
    # For PCAP/log specific findings
    source_ip: Optional[str] = Field(None, description="Source IP (for network events)")
    destination_ip: Optional[str] = Field(None, description="Destination IP (for network events)")
    protocol: Optional[str] = Field(None, description="Network protocol (for network events)")
    timestamp_observed: Optional[datetime] = Field(None, description="When the event was observed")


class ParserMetadata(BaseModel):
    """Metadata about the parsing process."""
    parser_name: str = Field(..., description="Name of the parser used")
    parser_version: str = Field(default="1.0.0", description="Version of the parser")
    processed_at: datetime = Field(default_factory=datetime.utcnow, description="When processing occurred")
    processing_time_ms: Optional[int] = Field(None, description="Time taken to process in milliseconds")
    warnings: list[str] = Field(default_factory=list, description="Any warnings during parsing")
    errors: list[str] = Field(default_factory=list, description="Any non-fatal errors during parsing")


class IngestedPacket(BaseModel):
    """
    The main output of Section 1: A normalized packet of security data.
    
    This packet contains all findings from a source document, normalized
    into a consistent structure ready for Section 2 processing.
    """
    # Identification
    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique packet identifier")
    
    # Source information
    source_type: SourceType = Field(..., description="Type of source document")
    source_file: str = Field(..., description="Original filename")
    source_hash: Optional[str] = Field(None, description="SHA-256 hash of source file for deduplication")
    
    # Timing
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the packet was created")
    report_date: Optional[datetime] = Field(None, description="Date of the original report (if extractable)")
    
    # The actual findings
    findings: list[Finding] = Field(default_factory=list, description="List of security findings")
    
    # Summary statistics (useful for quick overview)
    finding_count: int = Field(default=0, description="Total number of findings")
    critical_count: int = Field(default=0, description="Number of critical findings")
    high_count: int = Field(default=0, description="Number of high severity findings")
    
    # Processing metadata
    metadata: ParserMetadata = Field(..., description="Information about the parsing process")
    
    # Raw document summary (for context)
    document_summary: Optional[str] = Field(None, description="Executive summary if available")
    
    def model_post_init(self, __context) -> None:
        """Calculate summary statistics after initialization."""
        self.finding_count = len(self.findings)
        self.critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
    
    def to_prompt_context(self) -> str:
        """
        Format the packet as context for LLM prompts in Section 2.
        
        Returns a concise string representation suitable for injection
        into the Reporter model's context window.
        """
        lines = [
            f"Source: {self.source_file} ({self.source_type.value})",
            f"Findings: {self.finding_count} total ({self.critical_count} critical, {self.high_count} high)",
            "",
            "--- Findings ---",
        ]
        
        for i, finding in enumerate(self.findings, 1):
            lines.append(f"\n[{i}] {finding.title} ({finding.severity.value.upper()})")
            lines.append(f"    {finding.description[:500]}...")
            if finding.cve_ids:
                lines.append(f"    CVEs: {', '.join(finding.cve_ids)}")
            if finding.affected_assets:
                assets = [a.identifier for a in finding.affected_assets[:5]]
                lines.append(f"    Affected: {', '.join(assets)}")
        
        return "\n".join(lines)
