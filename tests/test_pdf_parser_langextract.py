"""
Tests for PDF Parser LangExtract (LLM-powered PDF parser)

Tests the LangExtract-based PDF parser for vulnerability report extraction.
Uses mocking to avoid requiring actual PDF files or API calls.
"""

import pytest
import os
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open
from tempfile import NamedTemporaryFile

from src.section1_ingestion.parsers.pdf_parser_langextract import PDFParserLangExtract
from src.section1_ingestion.schemas import Finding, Severity, AffectedAsset, SourceType


class TestPDFParserLangExtractInitialization:
    """Test parser initialization and configuration."""
    
    def test_init_with_api_key(self):
        """Test initialization with explicit API key."""
        with patch('pathlib.Path.exists', return_value=True):
            parser = PDFParserLangExtract(
                "test.pdf",
                api_key="test-key-123"
            )
            
            assert parser.api_key == "test-key-123"
            assert parser.file_path.name == "test.pdf"
            assert parser.model_id == "gemini-2.0-flash"
    
    def test_init_with_custom_model(self):
        """Test initialization with custom model ID."""
        with patch('pathlib.Path.exists', return_value=True):
            parser = PDFParserLangExtract(
                "test.pdf",
                model_id="gemini-1.5-pro",
                api_key="key"
            )
            
            assert parser.model_id == "gemini-1.5-pro"
    
    def test_init_reads_api_key_from_env(self):
        """Test reading API key from environment variable."""
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "env-key"}):
            with patch('pathlib.Path.exists', return_value=True):
                parser = PDFParserLangExtract("test.pdf")
                
                assert parser.api_key == "env-key"
    
    def test_init_explicit_api_key_overrides_env(self):
        """Test that explicit API key overrides environment variable."""
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "env-key"}):
            with patch('pathlib.Path.exists', return_value=True):
                parser = PDFParserLangExtract(
                    "test.pdf",
                    api_key="explicit-key"
                )
                
                assert parser.api_key == "explicit-key"
    
    def test_init_nonexistent_file_raises(self):
        """Test that nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            PDFParserLangExtract("nonexistent.pdf", api_key="key")
    
    def test_init_unsupported_extension_raises(self):
        """Test that unsupported file extension raises ValueError."""
        with patch('pathlib.Path.exists', return_value=True):
            with pytest.raises(ValueError):
                PDFParserLangExtract("test.txt", api_key="key")
    
    def test_parser_name_and_version(self):
        """Test parser metadata."""
        assert PDFParserLangExtract.PARSER_NAME == "pdf_parser_langextract"
        assert PDFParserLangExtract.PARSER_VERSION == "1.0.0"
        assert PDFParserLangExtract.SOURCE_TYPE == SourceType.VULNERABILITY_REPORT
        assert ".pdf" in PDFParserLangExtract.SUPPORTED_EXTENSIONS


class TestPDFParserLangExtractSeverityParsing:
    """Test severity level parsing from strings."""
    
    @pytest.fixture
    def parser(self):
        """Create a parser instance for testing."""
        with patch('pathlib.Path.exists', return_value=True):
            return PDFParserLangExtract("test.pdf", api_key="key")
    
    def test_parse_critical_severity(self, parser):
        """Test parsing critical severity."""
        severity = parser._parse_severity("critical")
        assert severity == Severity.CRITICAL
    
    def test_parse_high_severity(self, parser):
        """Test parsing high severity."""
        severity = parser._parse_severity("high")
        assert severity == Severity.HIGH
    
    def test_parse_medium_severity(self, parser):
        """Test parsing medium severity."""
        severity = parser._parse_severity("medium")
        assert severity == Severity.MEDIUM
    
    def test_parse_moderate_as_medium(self, parser):
        """Test that 'moderate' maps to MEDIUM."""
        severity = parser._parse_severity("moderate")
        assert severity == Severity.MEDIUM
    
    def test_parse_low_severity(self, parser):
        """Test parsing low severity."""
        severity = parser._parse_severity("low")
        assert severity == Severity.LOW
    
    def test_parse_info_severity(self, parser):
        """Test parsing informational severity."""
        severity = parser._parse_severity("informational")
        assert severity == Severity.INFO
    
    def test_parse_unknown_severity(self, parser):
        """Test parsing unknown severity returns UNKNOWN."""
        severity = parser._parse_severity("unknown")
        assert severity == Severity.UNKNOWN
    
    def test_parse_empty_severity(self, parser):
        """Test parsing empty string returns UNKNOWN."""
        severity = parser._parse_severity("")
        assert severity == Severity.UNKNOWN
    
    def test_parse_severity_case_insensitive(self, parser):
        """Test severity parsing is case-insensitive."""
        assert parser._parse_severity("CRITICAL") == Severity.CRITICAL
        assert parser._parse_severity("High") == Severity.HIGH
        assert parser._parse_severity("MeDiUm") == Severity.MEDIUM


class TestPDFParserLangExtractExtractionConversion:
    """Test conversion of LangExtract extractions to Finding objects."""
    
    @pytest.fixture
    def parser(self):
        """Create a parser instance for testing."""
        with patch('pathlib.Path.exists', return_value=True):
            return PDFParserLangExtract("test.pdf", api_key="key")
    
    def test_extraction_to_finding_basic(self, parser):
        """Test converting basic extraction to Finding."""
        mock_extraction = Mock()
        mock_extraction.extraction_text = "SQL Injection Vulnerability"
        mock_extraction.attributes = {
            "severity": "critical",
            "title": "SQL Injection",
            "description": "Database is vulnerable to SQL injection",
        }
        
        finding = parser._extraction_to_finding(mock_extraction)
        
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.CRITICAL
        assert finding.title == "SQL Injection"
        assert "SQL injection" in finding.description
    
    def test_extraction_with_affected_hosts_list(self, parser):
        """Test extraction with affected hosts as list."""
        mock_extraction = Mock()
        mock_extraction.extraction_text = "Test"
        mock_extraction.attributes = {
            "severity": "high",
            "title": "Test Finding",
            "description": "Test",
            "affected_hosts": ["192.168.1.1", "192.168.1.2"]
        }
        
        finding = parser._extraction_to_finding(mock_extraction)
        
        assert len(finding.affected_assets) == 2
        assert finding.affected_assets[0].identifier in ["192.168.1.1", "192.168.1.2"]
    
    def test_extraction_with_affected_hosts_string(self, parser):
        """Test extraction with affected hosts as comma-separated string."""
        mock_extraction = Mock()
        mock_extraction.extraction_text = "Test"
        mock_extraction.attributes = {
            "severity": "medium",
            "title": "Test",
            "description": "Test",
            "affected_hosts": "10.0.0.1, 10.0.0.2, 10.0.0.3"
        }
        
        finding = parser._extraction_to_finding(mock_extraction)
        
        assert len(finding.affected_assets) == 3
    
    def test_extraction_with_cve_ids_list(self, parser):
        """Test extraction with CVE IDs as list."""
        mock_extraction = Mock()
        mock_extraction.extraction_text = "Test"
        mock_extraction.attributes = {
            "severity": "high",
            "title": "Test",
            "description": "Test",
            "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"]
        }
        
        finding = parser._extraction_to_finding(mock_extraction)
        
        assert len(finding.cve_ids) == 2
        assert "CVE-2024-1234" in finding.cve_ids
    
    def test_extraction_with_cve_ids_string(self, parser):
        """Test extraction with CVE IDs as string."""
        mock_extraction = Mock()
        mock_extraction.extraction_text = "Test"
        mock_extraction.attributes = {
            "severity": "critical",
            "title": "Test",
            "description": "Test",
            "cve_ids": "CVE-2024-1111, CVE-2024-2222 and CVE-2024-3333"
        }
        
        finding = parser._extraction_to_finding(mock_extraction)
        
        assert len(finding.cve_ids) == 3
        assert "CVE-2024-1111" in finding.cve_ids
    
    def test_extraction_with_cvss_score(self, parser):
        """Test extraction with CVSS score."""
        mock_extraction = Mock()
        mock_extraction.extraction_text = "Test"
        mock_extraction.attributes = {
            "severity": "critical",
            "title": "Test",
            "description": "Test",
            "cvss_score": 9.8
        }
        
        finding = parser._extraction_to_finding(mock_extraction)
        
        assert finding.cvss_score == 9.8
    
    def test_extraction_with_invalid_cvss_score(self, parser):
        """Test extraction with invalid CVSS score is ignored."""
        mock_extraction = Mock()
        mock_extraction.extraction_text = "Test"
        mock_extraction.attributes = {
            "severity": "high",
            "title": "Test",
            "description": "Test",
            "cvss_score": 15.0  # Invalid: > 10
        }
        
        finding = parser._extraction_to_finding(mock_extraction)
        
        assert finding.cvss_score is None
    
    def test_extraction_with_remediation(self, parser):
        """Test extraction with remediation."""
        mock_extraction = Mock()
        mock_extraction.extraction_text = "Test"
        mock_extraction.attributes = {
            "severity": "high",
            "title": "Test",
            "description": "Test",
            "remediation": "Apply security patch"
        }
        
        finding = parser._extraction_to_finding(mock_extraction)
        
        assert len(finding.recommendations) > 0
        assert "Apply security patch" in finding.recommendations


class TestPDFParserLangExtractTextExtraction:
    """Test PDF text extraction."""
    
    @pytest.fixture
    def parser(self):
        """Create a parser instance for testing."""
        with patch('pathlib.Path.exists', return_value=True):
            return PDFParserLangExtract("test.pdf", api_key="key")
    
    @patch('fitz.open')
    def test_extract_text_from_pdf(self, mock_fitz_open, parser):
        """Test extracting text from PDF."""
        # Mock PDF document
        mock_page1 = Mock()
        mock_page1.get_text.return_value = "Page 1 text"
        
        mock_page2 = Mock()
        mock_page2.get_text.return_value = "Page 2 text"
        
        mock_doc = Mock()
        mock_doc.__iter__.return_value = [mock_page1, mock_page2]
        mock_doc.__enter__.return_value = mock_doc
        mock_doc.__exit__.return_value = False
        
        mock_fitz_open.return_value = mock_doc
        
        text = parser._extract_text_from_pdf()
        
        assert "Page 1 text" in text
        assert "Page 2 text" in text
    
    @patch('fitz.open')
    def test_extract_text_handles_page_errors(self, mock_fitz_open, parser):
        """Test that text extraction handles page errors gracefully."""
        mock_page1 = Mock()
        mock_page1.get_text.return_value = "Page 1"
        
        mock_page2 = Mock()
        mock_page2.get_text.side_effect = Exception("Unable to extract")
        
        mock_doc = Mock()
        mock_doc.__iter__.return_value = [mock_page1, mock_page2]
        mock_doc.__enter__.return_value = mock_doc
        mock_doc.__exit__.return_value = False
        
        mock_fitz_open.return_value = mock_doc
        
        text = parser._extract_text_from_pdf()
        
        assert "Page 1" in text
        assert len(parser.warnings) > 0


class TestPDFParserLangExtractLangExtractAvailability:
    """Test handling of missing LangExtract dependency."""
    
    @patch('pathlib.Path.exists', return_value=True)
    def test_check_langextract_available(self, mock_exists):
        """Test detection of LangExtract availability."""
        with patch('builtins.__import__'):
            parser = PDFParserLangExtract("test.pdf", api_key="key")
            # This should not raise an error
            assert isinstance(parser._langextract_available, bool)
    
    @patch('pathlib.Path.exists', return_value=True)
    def test_parse_without_langextract(self, mock_exists):
        """Test parsing fails gracefully when LangExtract is not available."""
        with patch('pathlib.Path.exists', return_value=True):
            parser = PDFParserLangExtract("test.pdf", api_key="key")
            parser._langextract_available = False
            
            findings = parser.parse()
            
            assert findings == []
            assert len(parser.errors) > 0
    
    @patch('pathlib.Path.exists', return_value=True)
    def test_parse_without_api_key(self, mock_exists):
        """Test parsing fails when API key is not available."""
        with patch.dict(os.environ, {}, clear=True):
            with patch('pathlib.Path.exists', return_value=True):
                parser = PDFParserLangExtract("test.pdf")
                
                findings = parser.parse()
                
                assert findings == []
                assert len(parser.errors) > 0


class TestPDFParserLangExtractParsing:
    """Test the main parsing functionality."""
    
    @patch('pathlib.Path.exists', return_value=True)
    def test_parse_empty_pdf(self, mock_exists):
        """Test parsing empty PDF returns error."""
        with patch('pathlib.Path.exists', return_value=True):
            parser = PDFParserLangExtract("test.pdf", api_key="key")
            parser._langextract_available = True
            
            # Mock text extraction to return empty
            with patch.object(parser, '_extract_text_from_pdf', return_value=""):
                findings = parser.parse()
                
                assert findings == []
                assert len(parser.errors) > 0
    
    @patch('pathlib.Path.exists', return_value=True)
    @patch('fitz.open')
    def test_parse_with_valid_extractions(self, mock_fitz_open, mock_exists):
        """Test parsing with valid LangExtract results."""
        with patch('pathlib.Path.exists', return_value=True):
            parser = PDFParserLangExtract("test.pdf", api_key="key")
            parser._langextract_available = True
            
            # Mock PDF text
            mock_doc = Mock()
            mock_page = Mock()
            mock_page.get_text.return_value = "Test vulnerability content"
            mock_doc.__iter__.return_value = [mock_page]
            mock_doc.__enter__.return_value = mock_doc
            mock_doc.__exit__.return_value = False
            mock_fitz_open.return_value = mock_doc
            
            # Mock LangExtract result
            mock_extraction = Mock()
            mock_extraction.extraction_text = "SQL Injection"
            mock_extraction.attributes = {
                "severity": "critical",
                "title": "SQL Injection Vulnerability",
                "description": "Database vulnerability",
            }
            
            mock_result = Mock()
            mock_result.extractions = [mock_extraction]
            
            with patch('langextract.extract', return_value=mock_result):
                with patch('google.generativeai.configure'):
                    findings = parser.parse()
                    
                    assert len(findings) > 0
                    assert findings[0].severity == Severity.CRITICAL
    
    @patch('pathlib.Path.exists', return_value=True)
    def test_parse_handles_conversion_errors(self, mock_exists):
        """Test parsing handles errors during extraction conversion."""
        with patch('pathlib.Path.exists', return_value=True):
            parser = PDFParserLangExtract("test.pdf", api_key="key")
            parser._langextract_available = True
            
            with patch.object(parser, '_extract_text_from_pdf', return_value="Test"):
                # Mock broken extraction
                mock_extraction = Mock()
                mock_extraction.attributes = None  # This might cause issues
                mock_extraction.extraction_text = "Test"
                
                mock_result = Mock()
                mock_result.extractions = [mock_extraction]
                
                with patch('langextract.extract', return_value=mock_result):
                    with patch('google.generativeai.configure'):
                        # Should not raise, but add warnings
                        findings = parser.parse()
                        
                        # May have warnings but should complete
                        assert isinstance(findings, list)


class TestPDFParserLangExtractExtractionPrompt:
    """Test the extraction prompt generation."""
    
    @pytest.fixture
    def parser(self):
        """Create a parser instance for testing."""
        with patch('pathlib.Path.exists', return_value=True):
            return PDFParserLangExtract("test.pdf", api_key="key")
    
    def test_get_extraction_prompt(self, parser):
        """Test that extraction prompt is generated."""
        prompt = parser._get_extraction_prompt()
        
        assert isinstance(prompt, str)
        assert len(prompt) > 0
        assert "vulnerability" in prompt.lower()
        assert "severity" in prompt.lower()
    
    def test_get_few_shot_examples(self, parser):
        """Test that few-shot examples are generated."""
        with patch('langextract.data'):
            examples = parser._get_few_shot_examples()
            
            assert isinstance(examples, list)
            # Should have at least a few examples
            assert len(examples) >= 1


class TestPDFParserLangExtractDocumentSummary:
    """Test document summary extraction."""
    
    @pytest.fixture
    def parser(self):
        """Create a parser instance for testing."""
        with patch('pathlib.Path.exists', return_value=True):
            return PDFParserLangExtract("test.pdf", api_key="key")
    
    def test_extract_summary_from_text(self, parser):
        """Test extracting summary from document text."""
        parser.full_text = "This is a summary paragraph with enough text.\n\nAnother paragraph."
        
        summary = parser.extract_document_summary()
        
        assert summary is not None
        assert "summary" in summary.lower()
    
    def test_extract_summary_empty_document(self, parser):
        """Test summary extraction from empty document."""
        parser.full_text = ""
        
        summary = parser.extract_document_summary()
        
        assert summary is None
    
    def test_extract_summary_short_document(self, parser):
        """Test summary extraction when document has no substantial paragraphs."""
        parser.full_text = "Short.\n\nText."
        
        summary = parser.extract_document_summary()
        
        # May return None if no substantial paragraphs


class TestPDFParserLangExtractErrorHandling:
    """Test error handling and logging."""
    
    @pytest.fixture
    def parser(self):
        """Create a parser instance for testing."""
        with patch('pathlib.Path.exists', return_value=True):
            return PDFParserLangExtract("test.pdf", api_key="key")
    
    def test_add_warning(self, parser):
        """Test adding warnings."""
        parser.add_warning("Test warning")
        
        assert len(parser.warnings) == 1
        assert "Test warning" in parser.warnings
    
    def test_add_error(self, parser):
        """Test adding errors."""
        parser.add_error("Test error")
        
        assert len(parser.errors) == 1
        assert "Test error" in parser.errors
    
    def test_multiple_warnings_and_errors(self, parser):
        """Test accumulating multiple warnings and errors."""
        parser.add_warning("Warning 1")
        parser.add_warning("Warning 2")
        parser.add_error("Error 1")
        
        assert len(parser.warnings) == 2
        assert len(parser.errors) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
