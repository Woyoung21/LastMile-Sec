

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
    SUMMARY_PROMPT_VERSION: str = "summary_v4"

    # Generation parameters
    SUMMARY_MAX_TOKENS: int = 150
    SUMMARY_TEMPERATURE: float = 0.3  # Lower = more deterministic
    SUMMARY_TOP_P: float = 0.9

    # Processing
    # Kept for future expansion if you later batch or parallelize requests.
    MAX_CONCURRENT_REQUESTS: int = 1
    REQUEST_TIMEOUT_SECONDS: int = 30
    # Retries are implemented via src.common.gemini_transient (env GEMINI_MAX_ATTEMPTS, etc.).
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
    REQUIRE_RAG: bool = os.getenv("ATTACK_MAPPER_REQUIRE_RAG", "true").lower() == "true"
    REQUIRE_CUDA: bool = os.getenv("ATTACK_MAPPER_REQUIRE_CUDA", "true").lower() == "true"
    LOCAL_CUDA_DEVICE: int = int(os.getenv("ATTACK_MAPPER_LOCAL_CUDA_DEVICE", "0"))
    ENABLE_TIMING: bool = os.getenv("ATTACK_MAPPER_ENABLE_TIMING", "true").lower() == "true"
    LOCAL_MAX_NEW_TOKENS: int = int(os.getenv("ATTACK_MAPPER_LOCAL_MAX_NEW_TOKENS", "50"))
    MIN_COLLECTION_VECTORS: int = int(os.getenv("ATTACK_MAPPER_MIN_COLLECTION_VECTORS", "1"))
    EXPECTED_EMBEDDING_DIM: int = int(os.getenv("ATTACK_MAPPER_EXPECTED_EMBEDDING_DIM", "384"))
    DEFAULT_ATTACK_CORPUS_PATH: Path = Path("data/corpus/enterprise-attack-18.1.json")

    # Cloud routing
    CLOUD_MODEL: str = "gemini-2.5-flash"

    # Local routing
    LOCAL_BASE_MODEL: str = "mistralai/Mistral-7B-Instruct-v0.1"
    LOCAL_ADAPTER_PATH: Path = Path(
        os.getenv(
            "ATTACK_MAPPER_LOCAL_ADAPTER_PATH",
            r"C:\Users\WillYoung\Downloads\CSC699\final_adapter_v3",
        )
    )

    # Retrieval / embeddings
    EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    VECTOR_DB_TOP_K: int = 1
    # Retrieve this many neighbors from VectorAI, rerank to tactic-aligned examples, then keep TOP_K.
    RERANK_POOL_K: int = int(os.getenv("ATTACK_MAPPER_RERANK_POOL_K", "8"))
    VECTOR_DB_ADDRESS: str = os.getenv("ATTACK_MAPPER_VECTOR_DB_ADDRESS", "localhost:50051")
    VECTOR_DB_COLLECTION: str = os.getenv("ATTACK_MAPPER_VECTOR_DB_COLLECTION", "mitre_v18_1")

    # MITRE ATT&CK enterprise framework version
    ATTACK_FRAMEWORK: str = "enterprise"
    # Current ATT&CK content version as of Feb 2026.
    ATTACK_VERSION: str = "18.1"

    # Technique mapping settings
    MIN_CONFIDENCE_THRESHOLD: float = 0.7
    MAX_TECHNIQUES_PER_FINDING: int = 5
    # When T1102 is semantically rejected and nothing remains, inject T1190 if the summary matches Initial Access heuristics.
    T1102_FALLBACK_T1190: bool = os.getenv("ATTACK_MAPPER_T1102_FALLBACK_T1190", "true").lower() == "true"

    # Tactic categories to consider
    ENABLED_TACTICS = [
        "reconnaissance",
        "resource-development",
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

    # Full MITRE ATT&CK Enterprise technique root IDs (v18.1, Oct 2025).
    # The validator accepts any sub-technique (e.g. T1059.001) whose root
    # ID is present in this set, so we only need root IDs here.
    DEFAULT_ENTERPRISE_18_1_TECHNIQUE_IDS = {
        # Reconnaissance
        "T1595", "T1592", "T1589", "T1590", "T1591", "T1598", "T1597",
        "T1596", "T1593", "T1594",
        # Resource Development
        "T1583", "T1586", "T1584", "T1587", "T1585", "T1588", "T1608",
        "T1650",
        # Initial Access
        "T1189", "T1190", "T1133", "T1200", "T1566", "T1091", "T1195",
        "T1199", "T1078", "T1659",
        # Execution
        "T1059", "T1609", "T1610", "T1203", "T1559", "T1106", "T1053",
        "T1129", "T1072", "T1569", "T1204", "T1047",
        # Persistence
        "T1098", "T1197", "T1547", "T1037", "T1176", "T1554", "T1136",
        "T1543", "T1546", "T1133", "T1574", "T1525", "T1556", "T1137",
        "T1542", "T1053", "T1505", "T1205", "T1078",
        # Privilege Escalation
        "T1548", "T1134", "T1547", "T1037", "T1543", "T1484", "T1546",
        "T1068", "T1574", "T1055", "T1053", "T1078",
        # Defense Evasion
        "T1548", "T1134", "T1197", "T1612", "T1622", "T1140", "T1610",
        "T1006", "T1484", "T1480", "T1211", "T1222", "T1564", "T1574",
        "T1562", "T1070", "T1202", "T1036", "T1556", "T1578", "T1112",
        "T1601", "T1599", "T1027", "T1647", "T1542", "T1055", "T1620",
        "T1207", "T1014", "T1553", "T1218", "T1216", "T1221", "T1205",
        "T1127", "T1535", "T1550", "T1078", "T1497", "T1600", "T1220",
        # Credential Access
        "T1557", "T1110", "T1555", "T1212", "T1187", "T1606", "T1056",
        "T1556", "T1111", "T1621", "T1040", "T1003", "T1528", "T1649",
        "T1558", "T1539", "T1552",
        # Discovery
        "T1087", "T1010", "T1217", "T1580", "T1538", "T1526", "T1619",
        "T1613", "T1622", "T1482", "T1083", "T1615", "T1046", "T1135",
        "T1040", "T1201", "T1120", "T1069", "T1057", "T1012", "T1018",
        "T1518", "T1082", "T1614", "T1016", "T1049", "T1033", "T1007",
        "T1124", "T1497",
        # Lateral Movement
        "T1210", "T1534", "T1570", "T1563", "T1021", "T1091", "T1072",
        "T1080", "T1550",
        # Collection
        "T1557", "T1560", "T1123", "T1119", "T1185", "T1115", "T1530",
        "T1602", "T1213", "T1005", "T1039", "T1025", "T1074", "T1114",
        "T1056", "T1113", "T1125",
        # Command and Control
        "T1071", "T1092", "T1132", "T1001", "T1568", "T1573", "T1008",
        "T1105", "T1104", "T1095", "T1571", "T1572", "T1090", "T1219",
        "T1205", "T1102",
        # Exfiltration
        "T1020", "T1030", "T1048", "T1041", "T1011", "T1052", "T1567",
        "T1029", "T1537",
        # Impact
        "T1531", "T1485", "T1486", "T1565", "T1491", "T1561", "T1499",
        "T1495", "T1490", "T1498", "T1496", "T1489", "T1529",
    }
