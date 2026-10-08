"""
CyberGuard Port Scanner Module.

Wraps the core network scanning engine to perform TCP connect scanning,
format terminal outputs, present authorization warnings, and produce risk findings.
"""

from typing import List, Optional

from config import DEFAULT_MAX_WORKERS, DEFAULT_PORT_RANGE, DEFAULT_SCAN_TIMEOUT
from core.logger import get_logger
from core.risk_engine import RiskEngine
from core.scanner import AUTHORIZATION_WARNING, HostScanSummary, NetworkScanner

logger = get_logger("modules.port_scanner")


class PortScannerModule:
    """High-level module interface for TCP port scanning operations."""

    @staticmethod
    def display_authorization_warning() -> None:
        """Prints the mandatory legal authorization notice."""
        print("\n" + "=" * 60)
        print(AUTHORIZATION_WARNING)
        print("=" * 60 + "\n")

    @classmethod
    def scan(
        cls,
        target: str,
        port_spec: str = DEFAULT_PORT_RANGE,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
        max_workers: int = DEFAULT_MAX_WORKERS,
        display_warning: bool = True,
    ) -> HostScanSummary:
        """
        Executes a port scan against the target host and returns structured summary.
        """
        if display_warning:
            cls.display_authorization_warning()

        return NetworkScanner.scan_host(
            target=target,
            port_spec=port_spec,
            timeout=timeout,
            max_workers=max_workers,
        )

    @classmethod
    def format_terminal_report(cls, summary: HostScanSummary) -> str:
        """Formats the scan results into a clean terminal report string."""
        lines: List[str] = [
            "CyberGuard Network Scanner",
            "===========================",
            f"Target: {summary.target} ({summary.ip_address})",
            f"Ports Scanned: {summary.total_ports_scanned}",
            "",
            f"{'PORT':<8} {'STATE':<9} {'SERVICE':<14} {'RISK':<10}",
            "-" * 45,
        ]

        if summary.open_ports:
            for p in summary.open_ports:
                lines.append(f"{p.port:<8} {'OPEN':<9} {p.service:<14} {p.risk_level:<10}")
        else:
            lines.append("No open ports discovered in the scanned range.")

        lines.extend([
            "-" * 45,
            f"Scan completed in {summary.duration_seconds:.2f} seconds.",
            f"Open Ports: {len(summary.open_ports)}",
            "",
            "Security observations:",
        ])

        if summary.observations:
            for obs in summary.observations:
                lines.append(f"- {obs}")
        else:
            lines.append("- No immediate service exposures identified.")

        return "\n".join(lines)


def run_port_scan(
    target: str,
    ports: str = DEFAULT_PORT_RANGE,
    timeout: float = DEFAULT_SCAN_TIMEOUT,
    workers: int = DEFAULT_MAX_WORKERS,
    quiet_warning: bool = False,
) -> HostScanSummary:
    """Convenience helper to run port scanner and return results."""
    return PortScannerModule.scan(
        target=target,
        port_spec=ports,
        timeout=timeout,
        max_workers=workers,
        display_warning=not quiet_warning,
    )
