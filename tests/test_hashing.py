"""
Unit tests for CyberGuard Hashing and Hash Analyzer Modules.
"""

import hashlib
from pathlib import Path
import pytest

from core.hashing import HashingEngine
from modules.hash_analyzer import HashAnalyzerModule


def test_hash_text_known_vectors():
    """Validates text hashing against standard known cryptographic digests."""
    sample = "CyberGuard2026"

    for algo in ["sha256", "sha512", "sha1", "md5"]:
        digest, warning = HashingEngine.hash_text(sample, algorithm=algo)
        expected = hashlib.new(algo, sample.encode("utf-8")).hexdigest()
        assert digest == expected

        if algo in ("md5", "sha1"):
            assert warning is not None
            assert "WARNING" in warning
        else:
            assert warning is None


def test_hash_file_streaming(tmp_path: Path):
    """Ensures file hashing streams correctly and matches hashlib digest."""
    test_file = tmp_path / "stream_test.txt"
    content = b"Defensive Security Engineering File Stream Test" * 1000
    test_file.write_bytes(content)

    digest, warning = HashingEngine.hash_file(test_file, algorithm="sha256")
    expected = hashlib.sha256(content).hexdigest()

    assert digest == expected
    assert warning is None


def test_hash_file_not_found():
    """Hashing non-existent file should raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        HashingEngine.hash_file("non_existent_file_cyberguard.txt")


def test_invalid_algorithm_rejection():
    """Unsupported algorithm names must raise ValueError."""
    with pytest.raises(ValueError):
        HashingEngine.hash_text("test", algorithm="unsupported_crypto_algo")


def test_verify_hash_text_and_file(tmp_path: Path):
    """Validates verify_hash matches correctly and rejects tampered digests."""
    text = "IntegrityCheckPayload"
    correct_hash = hashlib.sha256(text.encode()).hexdigest()
    fake_hash = "0" * 64

    # Text verify
    is_match, digest, _ = HashingEngine.verify_hash(text, correct_hash, algorithm="sha256")
    assert is_match is True
    assert digest == correct_hash

    is_match_fake, _, _ = HashingEngine.verify_hash(text, fake_hash, algorithm="sha256")
    assert is_match_fake is False

    # File verify
    f = tmp_path / "payload.dat"
    f.write_text(text)

    f_match, _, _ = HashingEngine.verify_hash(f, correct_hash, algorithm="sha256", is_file=True)
    assert f_match is True

    f_fail, _, _ = HashingEngine.verify_hash(f, fake_hash, algorithm="sha256", is_file=True)
    assert f_fail is False


def test_constant_time_comparison():
    """Checks timing-safe comparison helper."""
    h1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    h2 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    h3 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    assert HashingEngine.compare_hashes(h1, h2) is True
    assert HashingEngine.compare_hashes(h1, h3) is False


def test_hash_all_supported(tmp_path: Path):
    """Ensures hash_all generates digests for all 4 supported algorithms."""
    test_f = tmp_path / "all_algo.txt"
    test_f.write_text("All algorithm batch check")

    results = HashAnalyzerModule.hash_all(test_f, is_file=True)
    assert set(results.keys()) == {"sha256", "sha512", "sha1", "md5"}
    for algo, dig in results.items():
        assert len(dig) > 0
