"""
Unit tests for CyberGuard Unified Security Assessment Report Generator.
"""

import json
from pathlib import Path
import pytest

from core.risk_engine import Finding, Severity
from reports.report_generator import ReportGenerator


def test_terminal_report_output():
    """Validates terminal report format and summary headers."""
    findings = [
        Finding(
            name="SSH Port Exposed",
            category="Network",
            severity=Severity.MEDIUM,
            description="Port 22 open",
            recommendation="Restrict IP access",
        ),
        Finding(
            name="Default Password Observed",
            category="Credentials",
            severity=Severity.HIGH,
            description="Weak credential policy",
            recommendation="Enforce 16-char passphrase policy",
        ),
    ]

    rep = ReportGenerator(target="audit-server-01", findings=findings)
    term_text = rep.generate_terminal_report()

    assert "CyberGuard Security Assessment" in term_text
    assert "Target: audit-server-01" in term_text
    assert "Overall Score: 70/100" in term_text
    assert "MEDIUM     Network            SSH Port Exposed" in term_text
    assert "Key Recommendations:" in term_text
    assert "1. Restrict IP access" in term_text
    assert "2. Enforce 16-char passphrase policy" in term_text


def test_json_report_file_generation(tmp_path: Path):
    """Validates machine-readable JSON report schema and file export."""
    findings = [
        Finding(
            name="Unauthenticated Redis",
            category="Database",
            severity=Severity.CRITICAL,
            description="Redis listening on 0.0.0.0",
            recommendation="Enable requirepass and bind 127.0.0.1",
        )
    ]

    out_file = tmp_path / "output_report.json"
    rep = ReportGenerator(target="10.0.0.5", findings=findings)
    json_str = rep.generate_json_report(output_file=out_file)

    assert out_file.is_file()
    data = json.loads(json_str)

    assert data["metadata"]["target"] == "10.0.0.5"
    assert data["assessment"]["overall_score"] == 65
    assert data["assessment"]["severity_breakdown"]["critical"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["name"] == "Unauthenticated Redis"


def test_html_report_file_generation(tmp_path: Path):
    """Validates standalone responsive HTML report generation and structure."""
    findings = [
        Finding(
            name="Outdated TLS Protocol",
            category="Cryptography",
            severity=Severity.MEDIUM,
            description="TLS 1.0/1.1 accepted",
            recommendation="Upgrade to TLS 1.3 only",
        )
    ]

    out_file = tmp_path / "output_report.html"
    rep = ReportGenerator(target="web.corp.local", findings=findings)
    html_text = rep.generate_html_report(output_file=out_file)

    assert out_file.is_file()
    assert "<!DOCTYPE html>" in html_text
    assert "CyberGuard Security Assessment" in html_text
    assert "web.corp.local" in html_text
    assert "Outdated TLS Protocol" in html_text
    assert "Upgrade to TLS 1.3 only" in html_text
