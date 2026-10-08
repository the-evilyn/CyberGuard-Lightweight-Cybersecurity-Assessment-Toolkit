"""
Unit tests for CyberGuard Security Log Analyzer Module.
"""

from pathlib import Path
import pytest

from core.risk_engine import Severity
from modules.log_analyzer import SecurityLogAnalyzer


def test_parse_structured_line():
    """Verifies parsing of standard pipe-delimited structured log lines."""
    line_fail = "2026-10-08 10:15:30 | 192.168.1.50 | admin | FAILED | Invalid password"
    ev_fail = SecurityLogAnalyzer.parse_line(line_fail)
    assert ev_fail is not None
    assert ev_fail.ip_address == "192.168.1.50"
    assert ev_fail.username == "admin"
    assert ev_fail.is_failure is True
    assert ev_fail.is_success is False

    line_succ = "2026-10-08 10:16:00 | 192.168.1.50 | admin | SUCCESS | Auth granted"
    ev_succ = SecurityLogAnalyzer.parse_line(line_succ)
    assert ev_succ is not None
    assert ev_succ.is_success is True
    assert ev_succ.is_failure is False


def test_parse_syslog_sshd_line():
    """Verifies regex parsing for standard Debian/Ubuntu sshd auth log lines."""
    line = "Oct  8 14:22:01 web01 sshd[9182]: Failed password for invalid user hacker from 203.0.113.5 port 44321 ssh2"
    ev = SecurityLogAnalyzer.parse_line(line)
    assert ev is not None
    assert ev.ip_address == "203.0.113.5"
    assert ev.username == "hacker"
    assert ev.is_failure is True


def test_analyze_file_brute_force_and_compromise(tmp_path: Path):
    """Detects brute-force threshold breaches and success-after-multiple-failures."""
    log_file = tmp_path / "test_auth.log"
    lines = [
        # 4 failures from 10.10.10.1
        "2026-10-08 12:00:01 | 10.10.10.1 | root | FAILED | Bad credentials",
        "2026-10-08 12:00:02 | 10.10.10.1 | root | FAILED | Bad credentials",
        "2026-10-08 12:00:03 | 10.10.10.1 | root | FAILED | Bad credentials",
        "2026-10-08 12:00:04 | 10.10.10.1 | root | FAILED | Bad credentials",
        # Then success!
        "2026-10-08 12:00:05 | 10.10.10.1 | root | SUCCESS | Accepted password",
        # Benign login from 192.168.1.10
        "2026-10-08 12:05:00 | 192.168.1.10 | developer | SUCCESS | Accepted key",
    ]
    log_file.write_text("\n".join(lines))

    result = SecurityLogAnalyzer.analyze_file(log_file, failure_threshold=3)

    assert result.total_events == 6
    assert result.failed_logins == 4
    assert result.successful_logins == 2

    assert len(result.suspicious_ips) == 1
    bad_ip = result.suspicious_ips[0]
    assert bad_ip.ip_address == "10.10.10.1"
    assert bad_ip.failed_attempts == 4
    assert bad_ip.success_after_failures is True
    assert bad_ip.severity in ("HIGH", "CRITICAL")
    assert "root" in result.targeted_privileged_accounts

    # Ensure findings generated
    assert len(result.findings) >= 1
    assert any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings)


def test_analyze_file_clean(tmp_path: Path):
    """Log file with only routine successful logins should produce INFO finding."""
    log_file = tmp_path / "clean_auth.log"
    lines = [
        "2026-10-08 12:00:01 | 192.168.1.5 | dev | SUCCESS | Login ok",
        "2026-10-08 12:05:01 | 192.168.1.6 | dev | SUCCESS | Login ok",
    ]
    log_file.write_text("\n".join(lines))

    result = SecurityLogAnalyzer.analyze_file(log_file, failure_threshold=5)
    assert result.failed_logins == 0
    assert len(result.suspicious_ips) == 0
    assert result.findings[0].severity == Severity.INFO


def test_format_terminal_report(tmp_path: Path):
    """Checks string output formatting for log analysis report."""
    log_file = tmp_path / "report_auth.log"
    log_file.write_text("2026-10-08 10:00:00 | 1.2.3.4 | admin | FAILED | Err\n")

    res = SecurityLogAnalyzer.analyze_file(log_file, failure_threshold=1)
    report = SecurityLogAnalyzer.format_terminal_report(res)

    assert "Security Log Analysis" in report
    assert "Total events: 1" in report
    assert "Failed logins: 1" in report
    assert "Suspicious IPs:" in report
    assert "Recommendations:" in report
