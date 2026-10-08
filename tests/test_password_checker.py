"""
Unit tests for CyberGuard Password Analyzer and Checker Module.
"""

import pytest

from core.password_analyzer import PasswordAnalyzer
from core.risk_engine import Severity
from modules.password_checker import PasswordCheckerModule


def test_password_weak_dictionary_match():
    """Validates that common weak passwords receive low scores and critical risk."""
    for weak_pwd in ["password", "123456", "admin", "welcome", "qwerty"]:
        res = PasswordAnalyzer.analyze(weak_pwd)
        assert res.score <= 10
        assert res.risk_level in ("HIGH", "CRITICAL")
        assert res.is_dictionary_match is True
        assert any("known" in pat.lower() or "dictionary" in pat.lower() for pat in res.identified_patterns)


def test_password_short_length_penalty():
    """Short passwords must receive low scores and specific length advice."""
    res = PasswordAnalyzer.analyze("Ab1!")
    assert res.score <= 20
    assert res.length == 4
    assert any("at least" in rec.lower() for rec in res.recommendations)


def test_password_strong_complexity():
    """Complex long passwords should achieve high scores and minimal/low risk."""
    complex_pwd = "V4l!d_S3cur3#P@ssw0rd_2026!"
    res = PasswordAnalyzer.analyze(complex_pwd)
    assert res.score >= 80
    assert res.risk_level in ("LOW", "MINIMAL")
    assert res.has_uppercase is True
    assert res.has_lowercase is True
    assert res.has_digits is True
    assert res.has_special is True
    assert res.diversity_count == 4
    assert res.nist_entropy_bits >= 80.0


def test_password_repetitive_pattern_detection():
    """Repeated identical characters should be detected and penalized."""
    res = PasswordAnalyzer.analyze("AAAAAAAbbbbb123!")
    assert res.has_repetitive_pattern is True
    assert any("repetitive" in r.lower() or "repeated" in r.lower() for r in res.recommendations)


def test_password_sequential_pattern_detection():
    """Sequential keyboard patterns like '1234' or 'qwerty' should be flagged."""
    res = PasswordAnalyzer.analyze("MySecretqwerty99!")
    assert res.has_sequential_pattern is True
    assert any("sequential" in r.lower() for r in res.recommendations)


def test_secure_password_generator():
    """Cryptographic password generator must satisfy requested length and char classes."""
    for length in [12, 16, 24, 32]:
        pwd = PasswordAnalyzer.generate_secure_password(length=length)
        assert len(pwd) == length
        # Must have diversity
        res = PasswordAnalyzer.analyze(pwd)
        assert res.diversity_count == 4
        assert res.score >= 70


def test_passphrase_generator():
    """Passphrase generator should produce words joined by the designated separator."""
    phrase = PasswordAnalyzer.generate_passphrase(words_count=5, separator=".")
    tokens = phrase.split(".")
    assert len(tokens) == 5
    for t in tokens:
        assert len(t) > 2
        assert t.isalpha()


def test_password_module_findings_conversion():
    """Password analysis results should correctly convert to risk engine findings."""
    weak_res = PasswordAnalyzer.analyze("123456")
    findings = PasswordCheckerModule.convert_to_findings(weak_res)
    assert len(findings) >= 1
    assert findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

    strong_res = PasswordAnalyzer.analyze("St0ng!P@ssphrase_2026_Saf3")
    strong_findings = PasswordCheckerModule.convert_to_findings(strong_res)
    assert len(strong_findings) >= 1
    assert strong_findings[0].severity in (Severity.LOW, Severity.INFO)


def test_terminal_report_formatting():
    """Ensures formatted terminal output string contains essential metrics."""
    res = PasswordAnalyzer.analyze("TestPassword123!")
    report = PasswordCheckerModule.format_terminal_report(res)
    assert "Password Security Analysis" in report
    assert f"Score: {res.score}/100" in report
    assert "Length: 16" in report
    assert "Recommendations:" in report
