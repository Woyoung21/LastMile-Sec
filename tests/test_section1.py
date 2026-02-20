"""
Tests for Section 1: Ingestion Pipeline
"""

import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import json

from src.section1_ingestion.schemas import (
    Finding, 
    IngestedPacket, 
    Severity, 
    SourceType,
    AffectedAsset,
    ParserMetadata,
)
from src.section1_ingestion.normalizer import Normalizer, ingest_file


class TestSchemas:
    """Test Pydantic schema models."""
    
    def test_finding_creation(self):
        """Test creating a Finding with minimal data."""
        finding = Finding(
            title="SQL Injection Vulnerability",
            description="The login form is vulnerable to SQL injection attacks."
        )
        
        assert finding.title == "SQL Injection Vulnerability"
        assert finding.severity == Severity.UNKNOWN
        assert finding.id is not None
    
    def test_finding_with_all_fields(self):
        """Test creating a Finding with all fields populated."""
        finding = Finding(
            severity=Severity.CRITICAL,
            title="Remote Code Execution",
            description="Unauthenticated RCE via deserialization",
            affected_assets=[
                AffectedAsset(identifier="192.168.1.10", asset_type="server")
            ],
            cve_ids=["CVE-2024-1234", "CVE-2024-5678"],
            cvss_score=9.8,
            recommendations=["Patch immediately", "Implement WAF"],
            source_ip="10.0.0.1",
            destination_ip="192.168.1.10",
            protocol="HTTP",
        )
        
        assert finding.severity == Severity.CRITICAL
        assert len(finding.cve_ids) == 2
        assert finding.cvss_score == 9.8
        assert len(finding.affected_assets) == 1
    
    def test_finding_cvss_validation(self):
        """Test CVSS score validation (must be 0-10)."""
        # Valid score
        finding = Finding(
            title="Test",
            description="Test",
            cvss_score=7.5
        )
        assert finding.cvss_score == 7.5
        
        # Invalid scores should raise validation error
        with pytest.raises(Exception):
            Finding(
                title="Test",
                description="Test",
                cvss_score=15.0  # Invalid: > 10
            )
    
    def test_ingested_packet_creation(self):
        """Test creating an IngestedPacket."""
        findings = [
            Finding(title="Finding 1", description="Desc 1", severity=Severity.CRITICAL),
            Finding(title="Finding 2", description="Desc 2", severity=Severity.HIGH),
            Finding(title="Finding 3", description="Desc 3", severity=Severity.LOW),
        ]
        
        packet = IngestedPacket(
            source_type=SourceType.VULNERABILITY_REPORT,
            source_file="test_report.pdf",
            findings=findings,
            metadata=ParserMetadata(parser_name="test_parser"),
        )
        
        assert packet.finding_count == 3
        assert packet.critical_count == 1
        assert packet.high_count == 1
        assert packet.source_type == SourceType.VULNERABILITY_REPORT
    
    def test_ingested_packet_to_json(self):
        """Test JSON serialization of IngestedPacket."""
        packet = IngestedPacket(
            source_type=SourceType.CSV_LOG,
            source_file="firewall.csv",
            findings=[
                Finding(title="Alert", description="Blocked connection")
            ],
            metadata=ParserMetadata(parser_name="csv_parser"),
        )
        
        json_str = packet.model_dump_json()
        data = json.loads(json_str)
        
        assert data['source_type'] == 'csv_log'
        assert data['source_file'] == 'firewall.csv'
        assert len(data['findings']) == 1
    
    def test_ingested_packet_to_prompt_context(self):
        """Test generating prompt context from packet."""
        packet = IngestedPacket(
            source_type=SourceType.VULNERABILITY_REPORT,
            source_file="report.pdf",
            findings=[
                Finding(
                    title="SQL Injection",
                    description="Vulnerable login form",
                    severity=Severity.HIGH,
                    cve_ids=["CVE-2024-1234"],
                )
            ],
            metadata=ParserMetadata(parser_name="pdf_parser"),
        )
        
        context = packet.to_prompt_context()
        
        assert "report.pdf" in context
        assert "SQL Injection" in context
        assert "HIGH" in context
        assert "CVE-2024-1234" in context


class TestNormalizer:
    """Test the Normalizer class."""
    
    def test_supported_extensions(self):
        """Test that normalizer has correct extension mappings."""
        normalizer = Normalizer()
        
        assert '.pdf' in normalizer.PARSER_MAP
        assert '.csv' in normalizer.PARSER_MAP
        assert '.pcap' in normalizer.PARSER_MAP
    
    def test_unsupported_extension_raises(self):
        """Test that unsupported extensions raise ValueError."""
        normalizer = Normalizer()
        
        with pytest.raises(ValueError, match="No parser available"):
            normalizer.get_parser("file.txt")
    
    def test_nonexistent_file_raises(self):
        """Test that nonexistent files raise FileNotFoundError."""
        normalizer = Normalizer()
        
        with pytest.raises(FileNotFoundError):
            normalizer.ingest("nonexistent.pdf")


class TestSeverityEnum:
    """Test severity level handling."""
    
    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
    
    def test_severity_comparison(self):
        """Test that severity can be compared."""
        finding_crit = Finding(title="A", description="A", severity=Severity.CRITICAL)
        finding_low = Finding(title="B", description="B", severity=Severity.LOW)
        
        assert finding_crit.severity == Severity.CRITICAL
        assert finding_low.severity != Severity.CRITICAL


# Integration tests (require actual files)
class TestIntegration:
    """Integration tests that require sample files."""
    
    def test_pdf_ingestion(self):
        """Test full PDF ingestion pipeline."""
        pdf_path = Path(__file__).parent.parent / "data" / "raw" / "Vulnerability Scan Report (By Device).pdf"
        
        if pdf_path.exists():
            normalizer = Normalizer()
            packet = normalizer.ingest(str(pdf_path))
            
            assert packet is not None
            assert packet.source_type == SourceType.VULNERABILITY_REPORT
            assert len(packet.findings) > 0
            print(f"PDF Test: Ingested {len(packet.findings)} findings")
        else:
            pytest.skip("Requires sample PDF file")
    
    def test_csv_ingestion(self):
        """Test full CSV ingestion pipeline."""
        csv_path = Path(__file__).parent.parent / "data" / "raw" / "Vulnerability Scan Report CSV.csv"
        
        if csv_path.exists():
            normalizer = Normalizer()
            packet = normalizer.ingest(str(csv_path))
            
            assert packet is not None
            assert packet.source_type == SourceType.CSV_LOG
            assert len(packet.findings) > 0
            print(f"CSV Test: Ingested {len(packet.findings)} findings")
        else:
            pytest.skip("Requires sample CSV file")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
