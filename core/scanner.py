"""
CyberGuard Network Port Scanner Core Engine.

Performs controlled, multi-threaded TCP connect port scanning with target validation,
service resolution, and baseline defensive risk classification.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import re
import socket
import time
from typing import Dict, List, Optional, Set, Tuple

from config import (
    COMMON_QUICK_PORTS,
    DEFAULT_MAX_WORKERS,
    DEFAULT_SCAN_TIMEOUT,
    WELL_KNOWN_SERVICES,
)
from core.logger import get_logger
from core.risk_engine import Finding, Severity

logger = get_logger("scanner")

AUTHORIZATION_WARNING: str = (
    "⚠️  AUTHORIZATION NOTICE:\n"
    "Only scan systems and networks you own or have explicit written authorization to test.\n"
    "Unauthorized port scanning may violate local and international cyber legislation."
)


@dataclass
class PortScanResult:
    """Represents the scan outcome for a single network port."""
    port: int
    is_open: bool
    service: str
    risk_level: str
    observation: str
    banner: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "port": self.port,
            "state": "OPEN" if self.is_open else "CLOSED",
            "service": self.service,
            "risk_level": self.risk_level,
            "observation": self.observation,
            "banner": self.banner,
        }


@dataclass
class HostScanSummary:
    """Comprehensive summary of a completed host port scan."""
    target: str
    ip_address: str
    start_time: str
    end_time: str
    duration_seconds: float
    total_ports_scanned: int
    open_ports: List[PortScanResult] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "ip_address": self.ip_address,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.duration_seconds, 2),
            "total_ports_scanned": self.total_ports_scanned,
            "open_ports_count": len(self.open_ports),
            "open_ports": [p.to_dict() for p in self.open_ports],
            "observations": self.observations,
            "findings": [f.to_dict() for f in self.findings],
        }


class NetworkScanner:
    """
    Controlled TCP connect scanner with thread pooling,
    service identification, and risk evaluation.
    """

    @staticmethod
    def validate_target(target: str) -> bool:
        """
        Validates target hostname or IP address format.
        """
        cleaned = target.strip()
        if not cleaned:
            return False

        # Check valid IPv4 or IPv6
        try:
            ipaddress.ip_address(cleaned)
            return True
        except ValueError:
            pass

        # Check valid Hostname/FQDN pattern (RFC 1123)
        hostname_regex = re.compile(
            r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])"
            r"(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$"
        )
        return bool(hostname_regex.match(cleaned))

    @staticmethod
    def resolve_target(target: str) -> str:
        """
        Resolves hostname to IP address.
        Raises socket.gaierror or ValueError on resolution failure.
        """
        if not NetworkScanner.validate_target(target):
            raise ValueError(f"Invalid target format: '{target}'")
        try:
            return socket.gethostbyname(target.strip())
        except socket.gaierror as err:
            logger.error("Failed to resolve target hostname %s: %s", target, err)
            raise socket.gaierror(f"Could not resolve target '{target}': {err}")

    @staticmethod
    def parse_port_range(port_spec: str) -> List[int]:
        """
        Parses port specifications.
        Supports:
          - 'common' (uses COMMON_QUICK_PORTS)
          - '80'
          - '1-1024'
          - '22,80,443'
          - '21,22,80-90,443'
        """
        spec = port_spec.strip().lower()
        if spec in ("common", "quick", "top"):
            return COMMON_QUICK_PORTS

        ports: Set[int] = set()
        parts = spec.split(",")

        for part in parts:
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_str, end_str = part.split("-", 1)
                try:
                    start_port = int(start_str.strip())
                    end_port = int(end_str.strip())
                except ValueError:
                    raise ValueError(f"Invalid port range element: '{part}'")

                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError(f"Port range must be within 1-65535, start <= end: '{part}'")

                for p in range(start_port, end_port + 1):
                    ports.add(p)
            else:
                try:
                    port = int(part)
                except ValueError:
                    raise ValueError(f"Invalid port number: '{part}'")

                if port < 1 or port > 65535:
                    raise ValueError(f"Port must be between 1 and 65535: {port}")
                ports.add(port)

        if not ports:
            raise ValueError(f"No valid ports extracted from '{port_spec}'")

        return sorted(list(ports))

    @classmethod
    def identify_service(cls, port: int) -> Tuple[str, str, str]:
        """
        Returns (service_name, baseline_risk_level, risk_description).
        """
        if port in WELL_KNOWN_SERVICES:
            return WELL_KNOWN_SERVICES[port]

        # Fallback to standard library getservbyport
        try:
            service_name = socket.getservbyport(port, "tcp").upper()
            return service_name, "INFO", f"Active service on port {port}"
        except (OSError, socket.error):
            return "UNKNOWN", "INFO", f"Unrecognized TCP service on port {port}"

    @classmethod
    def scan_single_port(
        cls, ip_address: str, port: int, timeout: float = DEFAULT_SCAN_TIMEOUT
    ) -> Optional[PortScanResult]:
        """
        Executes TCP connect scan on a single port.
        Returns PortScanResult if open, or None if closed/filtered.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                service, risk, observation = cls.identify_service(port)
                # Attempt lightweight banner grab (non-intrusive)
                banner: Optional[str] = None
                try:
                    sock.settimeout(0.5)
                    # Safe probe: read prompt if service sends one on connect (e.g. SSH/FTP)
                    recv_bytes = sock.recv(128)
                    if recv_bytes:
                        banner = recv_bytes.decode("utf-8", errors="ignore").strip()
                except (socket.timeout, OSError):
                    pass

                return PortScanResult(
                    port=port,
                    is_open=True,
                    service=service,
                    risk_level=risk,
                    observation=observation,
                    banner=banner,
                )
            return None
        except (socket.error, OSError):
            return None
        finally:
            sock.close()

    @classmethod
    def scan_host(
        cls,
        target: str,
        port_spec: str = "1-1024",
        timeout: float = DEFAULT_SCAN_TIMEOUT,
        max_workers: int = DEFAULT_MAX_WORKERS,
    ) -> HostScanSummary:
        """
        Executes a multi-threaded TCP connect scan across specified ports.
        """
        ip_addr = cls.resolve_target(target)
        ports = cls.parse_port_range(port_spec)

        logger.info(
            "Initiating scan on %s (%s) across %d ports with %d workers",
            target,
            ip_addr,
            len(ports),
            max_workers,
        )

        start_dt = datetime.now()
        start_time_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        start_perf = time.perf_counter()

        open_results: List[PortScanResult] = []

        # ThreadPoolExecutor for bounded concurrency
        actual_workers = min(max_workers, max(1, len(ports)))
        with ThreadPoolExecutor(max_workers=actual_workers) as executor:
            future_to_port = {
                executor.submit(cls.scan_single_port, ip_addr, port, timeout): port
                for port in ports
            }
            for future in as_completed(future_to_port):
                res = future.result()
                if res and res.is_open:
                    open_results.append(res)

        end_perf = time.perf_counter()
        end_dt = datetime.now()
        end_time_str = end_dt.strftime("%Y-%m-%d %H:%M:%S")
        duration = end_perf - start_perf

        open_results.sort(key=lambda x: x.port)

        # Build observations and Risk findings
        observations: List[str] = []
        findings: List[Finding] = []

        for p in open_results:
            obs = f"Port {p.port} ({p.service}) is OPEN - {p.observation}"
            observations.append(obs)

            # Map to risk engine finding
            severity = Severity(p.risk_level)
            finding = Finding(
                name=f"Exposed {p.service} Service (Port {p.port})",
                category="Network Exposure",
                severity=severity,
                description=f"Port {p.port} ({p.service}) was identified as open on {target}. {p.observation}",
                recommendation=(
                    f"If port {p.port} ({p.service}) is not strictly required for operations, "
                    f"close or restrict it via firewall rules."
                ),
                details={"port": p.port, "service": p.service, "banner": p.banner},
            )
            findings.append(finding)

        logger.info(
            "Scan completed for %s in %.2fs: %d open ports found",
            target,
            duration,
            len(open_results),
        )

        return HostScanSummary(
            target=target,
            ip_address=ip_addr,
            start_time=start_time_str,
            end_time=end_time_str,
            duration_seconds=duration,
            total_ports_scanned=len(ports),
            open_ports=open_results,
            observations=observations,
            findings=findings,
        )
