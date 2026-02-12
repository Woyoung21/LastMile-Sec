"""
Base parser class that all file-type parsers inherit from.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
import hashlib
import time

from ..schemas import Finding, ParserMetadata, SourceType


class BaseParser(ABC):
    """
    Abstract base class for all file parsers.
    
    Each parser must implement the `parse` method to extract
    findings from its specific file type.
    """
    
    # Override in subclasses
    PARSER_NAME: str = "base"
    PARSER_VERSION: str = "1.0.0"
    SUPPORTED_EXTENSIONS: list[str] = []
    SOURCE_TYPE: SourceType = SourceType.UNKNOWN
    
    def __init__(self, file_path: str | Path):
        """
        Initialize parser with a file path.
        
        Args:
            file_path: Path to the file to parse
        """
        self.file_path = Path(file_path)
        self._validate_file()
        self.warnings: list[str] = []
        self.errors: list[str] = []
    
    def _validate_file(self) -> None:
        """Validate that the file exists and has a supported extension."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        if self.file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported file type: {self.file_path.suffix}. "
                f"Supported: {self.SUPPORTED_EXTENSIONS}"
            )
    
    def get_file_hash(self) -> str:
        """Calculate SHA-256 hash of the file for deduplication."""
        sha256_hash = hashlib.sha256()
        with open(self.file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def add_warning(self, message: str) -> None:
        """Add a warning message during parsing."""
        self.warnings.append(message)
    
    def add_error(self, message: str) -> None:
        """Add a non-fatal error message during parsing."""
        self.errors.append(message)
    
    @abstractmethod
    def parse(self) -> list[Finding]:
        """
        Parse the file and extract security findings.
        
        Returns:
            List of Finding objects extracted from the file
        """
        pass
    
    def extract_document_summary(self) -> Optional[str]:
        """
        Extract an executive summary from the document if available.
        
        Override in subclasses for format-specific extraction.
        
        Returns:
            Summary string or None if not available
        """
        return None
    
    def run(self) -> tuple[list[Finding], ParserMetadata, Optional[str]]:
        """
        Execute the parser and return findings with metadata.
        
        Returns:
            Tuple of (findings, metadata, document_summary)
        """
        start_time = time.time()
        
        findings = self.parse()
        summary = self.extract_document_summary()
        
        processing_time_ms = int((time.time() - start_time) * 1000)
        
        metadata = ParserMetadata(
            parser_name=self.PARSER_NAME,
            parser_version=self.PARSER_VERSION,
            processing_time_ms=processing_time_ms,
            warnings=self.warnings,
            errors=self.errors,
        )
        
        return findings, metadata, summary
