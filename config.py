"""
CyberGuard Configuration Module.

Central configuration settings, paths, cybersecurity thresholds,
and protocol catalogs for the CyberGuard Assessment Toolkit.
"""

from pathlib import Path
from typing import Dict, List, Tuple

# Toolkit Metadata
APP_NAME: str = "CyberGuard"
APP_SUBTITLE: str = "Lightweight Cybersecurity Assessment Toolkit"
VERSION: str = "1.0.0"
AUTHOR: str = "the-evilyn"
BASE_REPO_ATTRIBUTION: str = "Based on educational concepts by karansoni15-create"

# Directory Layout
BASE_DIR: Path = Path(__file__).resolve().parent
LOGS_DIR: Path = BASE_DIR / "logs"
REPORTS_DIR: Path = BASE_DIR / "reports_output"
SAMPLES_DIR: Path = BASE_DIR / "samples"
DEFAULT_LOG_FILE: Path = LOGS_DIR / "cyberguard.log"

# Port Scanner Settings
DEFAULT_SCAN_TIMEOUT: float = 1.0
DEFAULT_MAX_WORKERS: int = 50
DEFAULT_PORT_RANGE: str = "1-1024"

# Well-known cybersecurity service mappings with baseline security risk profiles:
# (service_name, baseline_risk_level, risk_description)
WELL_KNOWN_SERVICES: Dict[int, Tuple[str, str, str]] = {
    21: ("FTP", "MEDIUM", "Cleartext file transfer protocol prone to credential sniffing."),
    22: ("SSH", "INFO", "Encrypted remote administrative shell (verify authentication & key strength)."),
    23: ("Telnet", "CRITICAL", "Legacy cleartext protocol transmitting credentials in plaintext."),
    25: ("SMTP", "LOW", "Mail transfer service (check for open relay vulnerability)."),
    53: ("DNS", "INFO", "Domain Name Service (check for open recursor / zone transfer)."),
    69: ("TFTP", "HIGH", "Trivial File Transfer Protocol with no authentication."),
    80: ("HTTP", "LOW", "Unencrypted web server (recommend TLS redirection to HTTPS)."),
    110: ("POP3", "MEDIUM", "Cleartext email retrieval service."),
    111: ("RPCBind", "MEDIUM", "Remote Procedure Call binder, often targeted for amplification/recon."),
    135: ("MSRPC", "HIGH", "Microsoft RPC endpoint mapper, frequent pivot point in internal networks."),
    139: ("NetBIOS-SSN", "HIGH", "NetBIOS Session Service, exposes network shares and metadata."),
    143: ("IMAP", "MEDIUM", "Cleartext mail retrieval protocol."),
    443: ("HTTPS", "INFO", "Encrypted TLS web communications."),
    445: ("SMB", "HIGH", "Server Message Block service, prone to EternalBlue and relay attacks."),
    512: ("rexec", "CRITICAL", "Legacy unencrypted remote execution daemon."),
    513: ("rlogin", "CRITICAL", "Legacy unencrypted remote login daemon."),
    514: ("rsh", "CRITICAL", "Legacy unencrypted remote shell daemon."),
    993: ("IMAPS", "INFO", "Encrypted IMAP over SSL/TLS."),
    995: ("POP3S", "INFO", "Encrypted POP3 over SSL/TLS."),
    1433: ("MSSQL", "HIGH", "Microsoft SQL Server database listener."),
    1521: ("Oracle-DB", "HIGH", "Oracle database listener."),
    2049: ("NFS", "HIGH", "Network File System (check for unauthenticated exports)."),
    3306: ("MySQL", "MEDIUM", "MySQL database listener."),
    3389: ("RDP", "HIGH", "Remote Desktop Protocol exposed to network."),
    5432: ("PostgreSQL", "MEDIUM", "PostgreSQL database listener."),
    5900: ("VNC", "HIGH", "Virtual Network Computing remote desktop (frequently weak authentication)."),
    6379: ("Redis", "CRITICAL", "Redis in-memory store (historically unauthenticated by default)."),
    8080: ("HTTP-Proxy", "LOW", "Alternate unencrypted HTTP service or administrative interface."),
    8443: ("HTTPS-Alt", "INFO", "Alternate encrypted HTTPS service."),
    9200: ("Elasticsearch", "HIGH", "Elasticsearch REST API (often accidentally left unauthenticated)."),
    27017: ("MongoDB", "HIGH", "MongoDB database listener (often targeted for ransomware if exposed)."),
}

COMMON_QUICK_PORTS: List[int] = sorted(list(WELL_KNOWN_SERVICES.keys()))

# Password Security Settings
MIN_PASSWORD_LENGTH: int = 12
RECOMMENDED_PASSWORD_LENGTH: int = 16

# Entropy thresholds (in bits of NIST/Shannon entropy)
ENTROPY_THRESHOLDS: Dict[str, float] = {
    "VERY_WEAK": 28.0,
    "WEAK": 40.0,
    "MODERATE": 60.0,
    "STRONG": 80.0,
}

# Local educational list of common weak/default passwords
COMMON_WEAK_PASSWORDS: List[str] = [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "welcome",
    "admin",
    "administrator",
    "root",
    "toor",
    "iloveyou",
    "monkey",
    "football",
    "login",
    "princess",
    "sunshine",
    "master",
    "pass1234",
    "password123",
    "admin123",
    "guest",
    "letmein",
    "trustno1",
    "default",
]

# Hashing & Integrity
SUPPORTED_HASH_ALGORITHMS: List[str] = ["sha256", "sha512", "sha1", "md5"]
DEFAULT_HASH_ALGORITHM: str = "sha256"
FILE_READ_CHUNK_SIZE: int = 65536  # 64 KB streaming chunks

ALGORITHM_SECURITY_WARNINGS: Dict[str, str] = {
    "md5": "WARNING: MD5 is cryptographically broken and prone to collision attacks. Retained strictly for educational and legacy checksum compatibility.",
    "sha1": "WARNING: SHA-1 is deprecated by NIST due to collision vulnerabilities. Avoid using for security integrity or digital signatures.",
}

# Log Analyzer Settings
DEFAULT_BRUTE_FORCE_THRESHOLD: int = 5
DEFAULT_AUTH_TIME_WINDOW: int = 300  # 5 minutes in seconds
SUSPICIOUS_DEFAULT_USERNAMES: List[str] = [
    "root",
    "admin",
    "administrator",
    "guest",
    "test",
    "user",
    "oracle",
    "postgres",
    "deploy",
    "backup",
]

# Risk Scoring Weights (Point deduction from 100 per finding)
SEVERITY_DEDUCTIONS: Dict[str, int] = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0,
}
