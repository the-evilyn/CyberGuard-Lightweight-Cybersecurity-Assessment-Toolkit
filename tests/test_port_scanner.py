"""
Unit tests for CyberGuard Port Scanner Core and Module.
"""

from unittest.mock import MagicMock, patch
import pytest

from core.risk_engine import Severity
from core.scanner import AUTHORIZATION_WARNING, HostScanSummary, NetworkScanner, PortScanResult
from modules.port_scanner import PortScannerModule


def test_validate_target():
    """Validates target parsing for IPv4, IPv6, localhost, and hostnames."""
    assert NetworkScanner.validate_target("127.0.0.1") is True
    assert NetworkScanner.validate_target("192.168.1.1") is True
    assert NetworkScanner.validate_target("::1") is True
    assert NetworkScanner.validate_target("localhost") is True
    assert NetworkScanner.validate_target("internal.corp.local") is True

    # Invalid targets
    assert NetworkScanner.validate_target("") is False
    assert NetworkScanner.validate_target("http://127.0.0.1") is False
    assert NetworkScanner.validate_target("invalid target with spaces") is False


def test_parse_port_range():
    """Checks port range parser for various valid and invalid formats."""
    assert NetworkScanner.parse_port_range("80") == [80]
    assert NetworkScanner.parse_port_range("22,80,443") == [22, 80, 443]
    assert NetworkScanner.parse_port_range("1-5") == [1, 2, 3, 4, 5]
    assert NetworkScanner.parse_port_range("common") == [21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 139, 143, 443, 445, 512, 513, 514, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

    with pytest.raises(ValueError):
        NetworkScanner.parse_port_range("invalid")

    with pytest.raises(ValueError):
        NetworkScanner.parse_port_range("70000")

    with pytest.raises(ValueError):
        NetworkScanner.parse_port_range("500-100")


def test_service_identification():
    """Verifies service lookup and baseline risk classification."""
    svc_ssh, risk_ssh, _ = NetworkScanner.identify_service(22)
    assert svc_ssh == "SSH"

    svc_telnet, risk_telnet, _ = NetworkScanner.identify_service(23)
    assert svc_telnet == "Telnet"
    assert risk_telnet == "CRITICAL"

    svc_http, risk_http, _ = NetworkScanner.identify_service(80)
    assert svc_http == "HTTP"


@patch("socket.socket")
def test_scan_single_port_mocked(mock_socket_cls):
    """Mocks socket to test open and closed port detection without network access."""
    mock_sock = MagicMock()
    mock_socket_cls.return_value = mock_sock

    # Case 1: Open Port (connect_ex returns 0)
    mock_sock.connect_ex.return_value = 0
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"

    res_open = NetworkScanner.scan_single_port("127.0.0.1", 22)
    assert res_open is not None
    assert res_open.is_open is True
    assert res_open.port == 22
    assert res_open.service == "SSH"
    assert "SSH-2.0" in (res_open.banner or "")

    # Case 2: Closed Port (connect_ex returns 111)
    mock_sock.connect_ex.return_value = 111
    res_closed = NetworkScanner.scan_single_port("127.0.0.1", 23)
    assert res_closed is None


@patch("core.scanner.NetworkScanner.resolve_target", return_value="127.0.0.1")
@patch("core.scanner.NetworkScanner.scan_single_port")
def test_scan_host_summary(mock_scan_single, mock_resolve):
    """Verifies that scan_host assembles findings, observations, and metrics."""
    # Mock port 80 as open, port 443 as closed
    def fake_scan(ip, port, timeout):
        if port == 80:
            return PortScanResult(
                port=80,
                is_open=True,
                service="HTTP",
                risk_level="LOW",
                observation="Unencrypted HTTP service",
            )
        return None

    mock_scan_single.side_effect = fake_scan

    summary = NetworkScanner.scan_host("127.0.0.1", port_spec="80,443", max_workers=2)

    assert summary.target == "127.0.0.1"
    assert summary.total_ports_scanned == 2
    assert len(summary.open_ports) == 1
    assert summary.open_ports[0].port == 80
    assert len(summary.findings) == 1
    assert summary.findings[0].severity == Severity.LOW

    # Check terminal formatting
    term_report = PortScannerModule.format_terminal_report(summary)
    assert "CyberGuard Network Scanner" in term_report
    assert "Target: 127.0.0.1" in term_report
    assert "80       OPEN      HTTP" in term_report
