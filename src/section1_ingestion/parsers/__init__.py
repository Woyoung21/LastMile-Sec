"""
Parsers for various input file formats.

Each parser is responsible for extracting relevant security information
from its respective file type and returning a list of Finding objects.

PDF Parsing Options:
- PDFParser: Regex-based, fast, no API calls, works offline
- PDFParserLangExtract: LLM-based, more accurate, requires Gemini API key
"""

from .pdf_parser import PDFParser
from .csv_parser import CSVParser
from .pcap_parser import PCAPParser
from .base_parser import BaseParser

# LangExtract parser is optional (requires API key)
try:
    from .pdf_parser_langextract import PDFParserLangExtract
    LANGEXTRACT_AVAILABLE = True
except ImportError:
    PDFParserLangExtract = None
    LANGEXTRACT_AVAILABLE = False

__all__ = [
    "BaseParser",
    "PDFParser",
    "PDFParserLangExtract",
    "CSVParser",
    "PCAPParser",
    "LANGEXTRACT_AVAILABLE",
]
