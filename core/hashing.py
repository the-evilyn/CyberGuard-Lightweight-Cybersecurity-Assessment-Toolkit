"""
CyberGuard Cryptographic Hashing Engine.

Provides secure hashing primitives for text strings and file streams,
safe timing-resistant verification, and deprecation warnings for weak legacy algorithms.
"""

import hashlib
import hmac
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

from config import (
    ALGORITHM_SECURITY_WARNINGS,
    DEFAULT_HASH_ALGORITHM,
    FILE_READ_CHUNK_SIZE,
    SUPPORTED_HASH_ALGORITHMS,
)
from core.logger import get_logger

logger = get_logger("hashing")


class HashingEngine:
    """
    Cryptographic hash generator and verifier.
    Supports standard digests: SHA-256, SHA-512, SHA-1, and MD5 (with security warnings).
    """

    @staticmethod
    def normalize_algorithm(algorithm: str) -> str:
        """
        Validates and standardizes the algorithm name.
        Raises ValueError if unsupported.
        """
        algo = algorithm.strip().lower()
        if algo not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(
                f"Unsupported hash algorithm '{algorithm}'. Supported: {', '.join(SUPPORTED_HASH_ALGORITHMS)}"
            )
        return algo

    @classmethod
    def get_algorithm_warning(cls, algorithm: str) -> Optional[str]:
        """Returns security deprecation advisory if using legacy algorithms (e.g. MD5, SHA-1)."""
        algo = cls.normalize_algorithm(algorithm)
        return ALGORITHM_SECURITY_WARNINGS.get(algo)

    @classmethod
    def hash_text(
        cls, text: str, algorithm: str = DEFAULT_HASH_ALGORITHM
    ) -> Tuple[str, Optional[str]]:
        """
        Generates a hexadecimal digest for the given text string.

        :param text: Input string to hash
        :param algorithm: Hashing algorithm (e.g., 'sha256', 'sha512', 'sha1', 'md5')
        :return: Tuple of (hex_digest, security_warning)
        """
        algo = cls.normalize_algorithm(algorithm)
        warning = cls.get_algorithm_warning(algo)
        if warning:
            logger.warning("Hashing with deprecated algorithm [%s]: %s", algo, warning)

        hasher = hashlib.new(algo)
        hasher.update(text.encode("utf-8"))
        digest = hasher.hexdigest()
        return digest, warning

    @classmethod
    def hash_file(
        cls,
        file_path: Union[str, Path],
        algorithm: str = DEFAULT_HASH_ALGORITHM,
        chunk_size: int = FILE_READ_CHUNK_SIZE,
    ) -> Tuple[str, Optional[str]]:
        """
        Streams a file from disk in chunks and calculates its hexadecimal digest.
        Chunk-based reading prevents high memory usage on large files.

        :param file_path: Path to target file
        :param algorithm: Hashing algorithm
        :param chunk_size: Size in bytes for chunked reading
        :return: Tuple of (hex_digest, security_warning)
        """
        algo = cls.normalize_algorithm(algorithm)
        warning = cls.get_algorithm_warning(algo)
        if warning:
            logger.warning("File hashing with deprecated algorithm [%s]: %s", algo, warning)

        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        hasher = hashlib.new(algo)
        with open(path, "rb") as stream:
            while chunk := stream.read(chunk_size):
                hasher.update(chunk)

        digest = hasher.hexdigest()
        return digest, warning

    @classmethod
    def hash_all_supported(cls, data: Union[str, Path], is_file: bool = False) -> Dict[str, str]:
        """
        Generates hashes for all supported algorithms for comparative analysis.

        :param data: Text string or file path
        :param is_file: True if data represents a file path
        :return: Dictionary mapping algorithm name to its hex digest
        """
        results: Dict[str, str] = {}
        for algo in SUPPORTED_HASH_ALGORITHMS:
            if is_file:
                digest, _ = cls.hash_file(Path(str(data)), algorithm=algo)
            else:
                digest, _ = cls.hash_text(str(data), algorithm=algo)
            results[algo] = digest
        return results

    @classmethod
    def verify_hash(
        cls,
        data: Union[str, Path],
        expected_hash: str,
        algorithm: str = DEFAULT_HASH_ALGORITHM,
        is_file: bool = False,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Verifies whether calculated digest matches expected digest.
        Uses constant-time comparison (hmac.compare_digest) to mitigate timing attacks.

        :param data: Text string or file path
        :param expected_hash: The known expected hash
        :param algorithm: Algorithm used
        :param is_file: True if data is a file path
        :return: Tuple of (is_match, calculated_digest, security_warning)
        """
        if is_file:
            calc_hash, warning = cls.hash_file(data, algorithm=algorithm)
        else:
            calc_hash, warning = cls.hash_text(str(data), algorithm=algorithm)

        is_match = hmac.compare_digest(
            calc_hash.strip().lower(), expected_hash.strip().lower()
        )
        return is_match, calc_hash, warning

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> bool:
        """
        Compares two existing hash digests in constant time.
        """
        return hmac.compare_digest(hash1.strip().lower(), hash2.strip().lower())
