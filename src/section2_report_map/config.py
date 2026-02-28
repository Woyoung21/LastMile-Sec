"""
Configuration for Section 2: Report & Mapper

Handles API credentials, model settings, cache versioning,
and processing parameters.
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
    # Gemini 2.0 Flash is deprecated. Use 2.5 Flash as the default replacement.
    GEMINI_MODEL: str = "gemini-2.5-flash"

    # Bump this whenever you materially change:
    # - reporter prompt text
    # - model choice
    # - summary validation logic
    # - evidence formatting / cache key inputs
    SUMMARY_PROMPT_VERSION: str = "summary_v2"

    # Generation parameters
    SUMMARY_MAX_TOKENS: int = 150
    SUMMARY_TEMPERATURE: float = 0.3  # Lower = more deterministic
    SUMMARY_TOP_P: float = 0.9

    # Processing
    # Kept for future expansion if you later batch or parallelize requests.
    MAX_CONCURRENT_REQUESTS: int = 1
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
            print("⚠️ Warning: GOOGLE_API_KEY not set. Gemini integration will fail.")
            print("   Set via: export GOOGLE_API_KEY='your-key-here'")
            return False
        return True


class ATTACKMapperConfig:
    """Configuration for the MITRE ATT&CK Mapper."""

    ROUTING_MODE: str = os.getenv("ATTACK_MAPPER_ROUTING_MODE", "local")

    # Cloud routing
    CLOUD_MODEL: str = "gemini-2.5-flash"

    # Local routing
    LOCAL_BASE_MODEL: str = "mistralai/Mistral-7B-Instruct-v0.2"
    LOCAL_ADAPTER_PATH: Path = Path("/content/drive/MyDrive/CSC699/HF/final_adapter")

    # Retrieval / embeddings
    EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    VECTOR_DB_TOP_K: int = 2
    VECTOR_DB_ADDRESS: str = os.getenv("ATTACK_MAPPER_VECTOR_DB_ADDRESS", "localhost:50051")
    VECTOR_DB_COLLECTION: str = os.getenv("ATTACK_MAPPER_VECTOR_DB_COLLECTION", "mitre_v18_1")

    # MITRE ATT&CK enterprise framework version
    ATTACK_FRAMEWORK: str = "enterprise"
    # Current ATT&CK content version as of Feb 2026.
    ATTACK_VERSION: str = "18.1"

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

    # Bootstrap registry used when a full Enterprise 18.1 export is not configured.
    DEFAULT_ENTERPRISE_18_1_TECHNIQUE_IDS = {
        "T1003",
        "T1021",
        "T1040",
        "T1046",
        "T1055",
        "T1059",
        "T1071",
        "T1078",
        "T1110",
        "T1133",
        "T1190",
        "T1499",
        "T1548",
    }
