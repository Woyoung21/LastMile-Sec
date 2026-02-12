"""
Normalizer: Orchestrates parsing and produces standardized JSON packets.

This module ties together all parsers and provides a clean interface
for ingesting files and producing IngestedPacket objects.
"""

import os
from pathlib import Path
from typing import Optional, Type, Literal
import json

from .schemas import IngestedPacket, SourceType, ParserMetadata
from .parsers.base_parser import BaseParser
from .parsers.pdf_parser import PDFParser
from .parsers.csv_parser import CSVParser
from .parsers.pcap_parser import PCAPParser

# Optional LangExtract parser
try:
    from .parsers.pdf_parser_langextract import PDFParserLangExtract
    LANGEXTRACT_AVAILABLE = True
except ImportError:
    PDFParserLangExtract = None
    LANGEXTRACT_AVAILABLE = False


# Type for PDF parser selection
PDFParserType = Literal["regex", "langextract", "auto"]


class Normalizer:
    """
    Main entry point for the ingestion pipeline.
    
    Takes raw files and produces normalized IngestedPacket objects
    that can be serialized to JSON for downstream processing.
    
    Args:
        output_dir: Optional directory to save processed JSON packets
        pdf_parser: Which PDF parser to use:
            - "regex": Fast, offline, pattern-based (default)
            - "langextract": LLM-powered, more accurate, requires GOOGLE_API_KEY
            - "auto": Use LangExtract if API key is set, else regex
        gemini_model: Model ID for LangExtract (default: gemini-2.0-flash)
    """
    
    # Map file extensions to parser classes (default: regex-based)
    PARSER_MAP: dict[str, Type[BaseParser]] = {
        '.pdf': PDFParser,
        '.csv': CSVParser,
        '.pcap': PCAPParser,
        '.pcapng': PCAPParser,
    }
    
    def __init__(
        self, 
        output_dir: Optional[str | Path] = None,
        pdf_parser: PDFParserType = "regex",
        gemini_model: str = "gemini-2.0-flash",
    ):
        """
        Initialize the normalizer.
        
        Args:
            output_dir: Optional directory to save processed JSON packets
            pdf_parser: Which PDF parser to use ("regex", "langextract", or "auto")
            gemini_model: Model ID for LangExtract parser
        """
        self.output_dir = Path(output_dir) if output_dir else None
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.pdf_parser_type = pdf_parser
        self.gemini_model = gemini_model
        
        # Resolve "auto" mode
        if pdf_parser == "auto":
            if LANGEXTRACT_AVAILABLE and os.getenv("GOOGLE_API_KEY"):
                self.pdf_parser_type = "langextract"
            else:
                self.pdf_parser_type = "regex"
    
    def get_parser(self, file_path: str | Path) -> BaseParser:
        """
        Get the appropriate parser for a file based on its extension.
        
        Args:
            file_path: Path to the file to parse
            
        Returns:
            Initialized parser instance
            
        Raises:
            ValueError: If no parser is available for the file type
        """
        file_path = Path(file_path)
        extension = file_path.suffix.lower()
        
        if extension not in self.PARSER_MAP:
            supported = ', '.join(self.PARSER_MAP.keys())
            raise ValueError(
                f"No parser available for '{extension}' files. "
                f"Supported formats: {supported}"
            )
        
        # Special handling for PDF based on configuration
        if extension == '.pdf':
            if self.pdf_parser_type == "langextract" and LANGEXTRACT_AVAILABLE:
                return PDFParserLangExtract(file_path, model_id=self.gemini_model)
            else:
                return PDFParser(file_path)
        
        parser_class = self.PARSER_MAP[extension]
        return parser_class(file_path)
    
    def ingest(self, file_path: str | Path) -> IngestedPacket:
        """
        Ingest a file and produce a normalized packet.
        
        Args:
            file_path: Path to the file to ingest
            
        Returns:
            IngestedPacket containing all extracted findings
        """
        file_path = Path(file_path)
        
        # Get the appropriate parser
        parser = self.get_parser(file_path)
        
        # Run the parser
        findings, metadata, summary = parser.run()
        
        # Build the packet
        packet = IngestedPacket(
            source_type=parser.SOURCE_TYPE,
            source_file=file_path.name,
            source_hash=parser.get_file_hash(),
            findings=findings,
            metadata=metadata,
            document_summary=summary,
        )
        
        return packet
    
    def ingest_and_save(self, file_path: str | Path) -> tuple[IngestedPacket, Path]:
        """
        Ingest a file and save the resulting JSON packet.
        
        Args:
            file_path: Path to the file to ingest
            
        Returns:
            Tuple of (IngestedPacket, path to saved JSON file)
            
        Raises:
            ValueError: If no output directory is configured
        """
        if not self.output_dir:
            raise ValueError("No output directory configured. Pass output_dir to constructor.")
        
        packet = self.ingest(file_path)
        
        # Generate output filename
        source_stem = Path(file_path).stem
        output_file = self.output_dir / f"{source_stem}_{packet.id[:8]}.json"
        
        # Save to JSON
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(packet.model_dump_json(indent=2))
        
        return packet, output_file
    
    def ingest_directory(
        self, 
        dir_path: str | Path, 
        recursive: bool = False
    ) -> list[IngestedPacket]:
        """
        Ingest all supported files in a directory.
        
        Args:
            dir_path: Path to directory containing files
            recursive: Whether to search subdirectories
            
        Returns:
            List of IngestedPacket objects
        """
        dir_path = Path(dir_path)
        packets = []
        
        pattern = '**/*' if recursive else '*'
        
        for ext in self.PARSER_MAP.keys():
            for file_path in dir_path.glob(f"{pattern}{ext}"):
                try:
                    packet = self.ingest(file_path)
                    packets.append(packet)
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
        
        return packets


def ingest_file(file_path: str | Path) -> IngestedPacket:
    """
    Convenience function to ingest a single file.
    
    Args:
        file_path: Path to the file to ingest
        
    Returns:
        IngestedPacket containing all extracted findings
        
    Example:
        >>> packet = ingest_file("report.pdf")
        >>> print(packet.model_dump_json(indent=2))
    """
    normalizer = Normalizer()
    return normalizer.ingest(file_path)


def ingest_to_json(file_path: str | Path, output_path: Optional[str | Path] = None) -> str:
    """
    Ingest a file and return JSON string.
    
    Args:
        file_path: Path to the file to ingest
        output_path: Optional path to save the JSON file
        
    Returns:
        JSON string representation of the IngestedPacket
    """
    packet = ingest_file(file_path)
    json_str = packet.model_dump_json(indent=2)
    
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(json_str)
    
    return json_str
