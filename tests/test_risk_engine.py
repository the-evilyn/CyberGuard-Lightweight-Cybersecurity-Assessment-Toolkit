"""
Unit tests for CyberGuard Transparent Risk Scoring Engine.
"""

import pytest

from core.risk_engine import Finding, RiskEngine, Severity


def test_base_score_clean():
    """An engine without findings should score 100 (Minimal Risk)."""
    engine = RiskEngine()
    summary = engine.get_summary()
    assert summary.overall_score == 100
    assert summary.risk_level == "MINIMAL RISK"
    assert summary.findings_count == 0


def test_severity_score_deductions():
    """Ensures each severity level deducts designated points."""
    engine = RiskEngine()
    engine.add_finding(
        Finding(
            name="Telnet Exposed",
            category="Network",
            severity=Severity.CRITICAL,  # -35
            description="Cleartext protocol",
            recommendation="Disable telnet",
        )
    )
    assert engine.calculate_score() == 65

    engine.add_finding(
        Finding(
            name="SSH Password Auth",
            category="Network",
            severity=Severity.HIGH,  # -20
            description="Use keys instead",
            recommendation="Disable PasswordAuthentication",
        )
    )
    assert engine.calculate_score() == 45

    engine.add_finding(
        Finding(
            name="FTP Exposed",
            category="Network",
            severity=Severity.MEDIUM,  # -10
            description="Cleartext FTP",
            recommendation="Use SFTP",
        )
    )
    assert engine.calculate_score() == 35

    engine.add_finding(
        Finding(
            name="HTTP Banner Disclosure",
            category="Web",
            severity=Severity.LOW,  # -5
            description="Server header visible",
            recommendation="Suppress banner",
        )
    )
    assert engine.calculate_score() == 30

    engine.add_finding(
        Finding(
            name="HTTPS Enabled",
            category="Web",
            severity=Severity.INFO,  # -0
            description="TLS active",
            recommendation="Keep updated",
        )
    )
    assert engine.calculate_score() == 30


def test_score_floor_at_zero():
    """Cumulative penalties should never drop the score below 0."""
    engine = RiskEngine()
    for _ in range(5):
        engine.add_finding(
            Finding(
                name="Critical Breach",
                category="General",
                severity=Severity.CRITICAL,
                description="Severe risk",
                recommendation="Immediate remediations",
            )
        )
    assert engine.calculate_score() == 0
    summary = engine.get_summary()
    assert summary.overall_score == 0
    assert summary.risk_level == "CRITICAL RISK"
    assert summary.critical_count == 5


def test_engine_serialization():
    """Validates serialization of findings and summary metrics."""
    engine = RiskEngine()
    engine.add_finding(
        Finding(
            name="Test Finding",
            category="Test",
            severity=Severity.LOW,
            description="Desc",
            recommendation="Rec",
        )
    )
    data = engine.to_dict()
    assert "summary" in data
    assert "findings" in data
    assert data["summary"]["overall_score"] == 95
    assert len(data["findings"]) == 1
    assert data["findings"][0]["name"] == "Test Finding"
