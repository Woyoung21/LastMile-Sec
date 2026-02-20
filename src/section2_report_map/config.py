"""
Configuration for Section 2: Report & Mapper

Handles API credentials, model settings, and processing parameters.
"""

import os
from pathlib import Path
from typing import Optional

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, will use existing env vars


class ReporterConfig:
    """Configuration for the Reporter module."""
    
    # Gemini/Google AI settings
    GEMINI_API_KEY: Optional[str] = os.getenv("GOOGLE_API_KEY")
    GEMINI_MODEL: str = "gemini-2.0-flash"  # Cost-effective model for batch processing
    
    # Generation parameters
    SUMMARY_MAX_TOKENS: int = 150
    SUMMARY_TEMPERATURE: float = 0.3  # Lower = more deterministic
    SUMMARY_TOP_P: float = 0.9
    
    # Processing
    MAX_CONCURRENT_REQUESTS: int = 1  # Respect rate limits like before
    REQUEST_TIMEOUT_SECONDS: int = 30
    RETRY_ATTEMPTS: int = 3
    RETRY_DELAY_SECONDS: int = 2
    
    # Cache settings (to avoid re-summarizing same findings)
    ENABLE_CACHE: bool = True
    CACHE_DIR: Path = Path(__file__).parent.parent.parent / "data" / "cache"
    
    @classmethod
    def ensure_cache_dir(cls):
        """Create cache directory if it doesn't exist."""
        cls.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def validate(cls) -> bool:
        """Validate configuration is properly set up."""
        if not cls.GEMINI_API_KEY:
            print("⚠️  Warning: GOOGLE_API_KEY not set. Gemini integration will fail.")
            print("   Set via: export GOOGLE_API_KEY='your-key-here'")
            return False
        return True


class ATTACKMapperConfig:
    """Configuration for the MITRE ATT&CK Mapper (future use)."""
    
    # MITRE ATT&CK enterprise framework version
    ATTACK_FRAMEWORK: str = "enterprise"
    ATTACK_VERSION: str = "13.0"  # Latest as of Feb 2026
    
    # Technique mapping settings
    MIN_CONFIDENCE_THRESHOLD: float = 0.7
    MAX_TECHNIQUES_PER_FINDING: int = 5
    
    # Tactic categories to consider
    ENABLED_TACTICS = [
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "exfiltration",
        "command-and-control",
        "impact",
    ]
