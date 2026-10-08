"""
CyberGuard Hash Analyzer Module.

Provides user-friendly cryptographic hashing, multi-algorithm batch hashing,
file integrity hashing, and timing-attack resilient verification.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from config import DEFAULT_HASH_ALGORITHM, SUPPORTED_HASH_ALGORITHMS
from core.hashing import HashingEngine
from core.logger import get_logger

logger = get_logger("modules.hash_analyzer")


class HashAnalyzerModule:
    """User-facing hash analysis and validation module."""

    @classmethod
    def hash_text(
        cls, text: str, algorithm: str = DEFAULT_HASH_ALGORITHM
    ) -> Tuple[str, Optional[str]]:
        """Generates hash digest for text."""
        return HashingEngine.hash_text(text, algorithm)

    @classmethod
    def hash_file(
        cls, file_path: Union[str, Path], algorithm: str = DEFAULT_HASH_ALGORITHM
    ) -> Tuple[str, Optional[str]]:
        """Generates streaming hash digest for a file."""
        return HashingEngine.hash_file(file_path, algorithm)

    @classmethod
    def hash_all(
        cls, target: Union[str, Path], is_file: bool = False
    ) -> Dict[str, str]:
        """Calculates all supported hashes for text or file."""
        return HashingEngine.hash_all_supported(target, is_file=is_file)

    @classmethod
    def verify(
        cls,
        data: Union[str, Path],
        expected_hash: str,
        algorithm: str = DEFAULT_HASH_ALGORITHM,
        is_file: bool = False,
    ) -> Tuple[bool, str, Optional[str]]:
        """Verifies calculated hash against expected hash."""
        return HashingEngine.verify_hash(
            data=data,
            expected_hash=expected_hash,
            algorithm=algorithm,
            is_file=is_file,
        )

    @classmethod
    def compare(cls, hash1: str, hash2: str) -> bool:
        """Constant-time comparison between two hash digests."""
        return HashingEngine.compare_hashes(hash1, hash2)

    @classmethod
    def format_all_hashes_report(
        cls, target_name: str, hashes: Dict[str, str], is_file: bool = False
    ) -> str:
        """Formats multi-algorithm hash summary for terminal output."""
        header = f"Cryptographic Hashes for {'File' if is_file else 'Text'}: {target_name}"
        lines: List[str] = [
            header,
            "=" * len(header),
            "",
            f"{'ALGORITHM':<10} {'HEXADECIMAL DIGEST'}",
            "-" * 76,
        ]

        for algo in SUPPORTED_HASH_ALGORITHMS:
            digest = hashes.get(algo, "N/A")
            lines.append(f"{algo.upper():<10} {digest}")

        lines.extend([
            "-" * 76,
            "Security Notes:",
            "- SHA-256 / SHA-512: Recommended for security applications and integrity verification.",
            "- MD5 / SHA-1: Deprecated due to known cryptographic collision weaknesses.",
        ])

        return "\n".join(lines)
