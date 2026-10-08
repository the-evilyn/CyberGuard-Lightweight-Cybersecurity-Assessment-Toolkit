"""
CyberGuard Security Log Analyzer Module.

Parses authentication event logs (structured and syslog/auth.log formats),
identifies brute-force patterns, repeated IP failures, privilege targeting,
and success-after-failure anomalies.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from config import (
    DEFAULT_AUTH_TIME_WINDOW,
    DEFAULT_BRUTE_FORCE_THRESHOLD,
    SUSPICIOUS_DEFAULT_USERNAMES,
)
from core.logger import get_logger
from core.risk_engine import Finding, Severity

logger = get_logger("modules.log_analyzer")


@dataclass
class LogEvent:
    """Represents a normalized authentication event."""
    timestamp: Optional[datetime]
    ip_address: str
    username: str
    is_failure: bool
    is_success: bool
    event_type: str
    raw_message: str


@dataclass
class SuspiciousIPProfile:
    """Security diagnostics for an IP address with anomalous authentication patterns."""
    ip_address: str
    failed_attempts: int
    successful_attempts: int
    targeted_users: List[str]
    severity: str
    success_after_failures: bool
    anomaly_reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "failed_attempts": self.failed_attempts,
            "successful_attempts": self.successful_attempts,
            "targeted_users": self.targeted_users,
            "severity": self.severity,
            "success_after_failures": self.success_after_failures,
            "reasons": self.anomaly_reasons,
        }


@dataclass
class LogAnalysisResult:
    """Comprehensive security evaluation outcome from log file parsing."""
    file_path: str
    total_events: int
    failed_logins: int
    successful_logins: int
    suspicious_ips: List[SuspiciousIPProfile] = field(default_factory=list)
    targeted_privileged_accounts: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "total_events": self.total_events,
            "failed_logins": self.failed_logins,
            "successful_logins": self.successful_logins,
            "suspicious_ips": [ip.to_dict() for ip in self.suspicious_ips],
            "targeted_privileged_accounts": self.targeted_privileged_accounts,
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": self.recommendations,
        }


class SecurityLogAnalyzer:
    """Defensive log parser and threat pattern detection engine."""

    # Regex for standard syslog/auth.log failed password
    SYSLOG_FAILED = re.compile(
        r"(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+Failed\s+password\s+(?:for\s+invalid\s+user\s+|for\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    )
    # Regex for standard syslog/auth.log accepted password
    SYSLOG_ACCEPTED = re.compile(
        r"(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    )

    @classmethod
    def parse_line(cls, line: str) -> Optional[LogEvent]:
        """
        Parses a single log line into a normalized LogEvent.
        Supports pipe-delimited structured logs and syslog sshd entries.
        """
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            return None

        # 1. Pipe-delimited structured format: TIMESTAMP | IP | USERNAME | STATUS | DETAILS
        if "|" in cleaned:
            parts = [p.strip() for p in cleaned.split("|")]
            if len(parts) >= 4:
                ts_str, ip_str, user_str, status_str = parts[0], parts[1], parts[2], parts[3]
                parsed_ts: Optional[datetime] = None
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        parsed_ts = datetime.strptime(ts_str, fmt)
                        break
                    except ValueError:
                        pass

                is_fail = "fail" in status_str.lower() or "error" in status_str.lower()
                is_succ = "success" in status_str.lower() or "ok" in status_str.lower() or "accept" in status_str.lower()

                return LogEvent(
                    timestamp=parsed_ts,
                    ip_address=ip_str,
                    username=user_str,
                    is_failure=is_fail,
                    is_success=is_succ,
                    event_type=status_str.upper(),
                    raw_message=cleaned,
                )

        # 2. Syslog Failed SSH
        m_fail = cls.SYSLOG_FAILED.search(cleaned)
        if m_fail:
            user = m_fail.group("user")
            ip = m_fail.group("ip")
            return LogEvent(
                timestamp=None,
                ip_address=ip,
                username=user,
                is_failure=True,
                is_success=False,
                event_type="AUTH_FAILURE",
                raw_message=cleaned,
            )

        # 3. Syslog Accepted SSH
        m_acc = cls.SYSLOG_ACCEPTED.search(cleaned)
        if m_acc:
            user = m_acc.group("user")
            ip = m_acc.group("ip")
            return LogEvent(
                timestamp=None,
                ip_address=ip,
                username=user,
                is_failure=False,
                is_success=True,
                event_type="AUTH_SUCCESS",
                raw_message=cleaned,
            )

        return None

    @classmethod
    def analyze_file(
        cls,
        file_path: Union[str, Path],
        failure_threshold: int = DEFAULT_BRUTE_FORCE_THRESHOLD,
    ) -> LogAnalysisResult:
        """
        Parses log file, tracks security heuristics, and identifies attack patterns.
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {path}")

        logger.info("Analyzing security log file: %s (threshold: %d)", path, failure_threshold)

        events: List[LogEvent] = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                event = cls.parse_line(line)
                if event:
                    events.append(event)

        total_events = len(events)
        failed_count = sum(1 for e in events if e.is_failure)
        success_count = sum(1 for e in events if e.is_success)

        # Aggregate per IP
        ip_events = defaultdict(list)
        for e in events:
            if e.ip_address:
                ip_events[e.ip_address].append(e)

        suspicious_ips: List[SuspiciousIPProfile] = []
        privileged_targeted: Set[str] = set()
        findings: List[Finding] = []
        recommendations: List[str] = [
            "Review authentication logs for repeated failed logins.",
            "Enforce rate limiting and account lockout policies for authentication endpoints.",
            "Implement multi-factor authentication (MFA) across all administrative services.",
        ]

        for ip, ev_list in ip_events.items():
            ip_fails = sum(1 for e in ev_list if e.is_failure)
            ip_successes = sum(1 for e in ev_list if e.is_success)
            users_seen = sorted(list({e.username for e in ev_list if e.username}))

            # Check if any privileged users targeted
            for u in users_seen:
                if u.lower() in SUSPICIOUS_DEFAULT_USERNAMES:
                    privileged_targeted.add(u)

            # Check success-after-multiple-failures anomaly
            success_after_failures = False
            consecutive_failures = 0
            for e in ev_list:
                if e.is_failure:
                    consecutive_failures += 1
                elif e.is_success:
                    if consecutive_failures >= 3:
                        success_after_failures = True
                        break
                    consecutive_failures = 0

            reasons: List[str] = []
            if ip_fails >= failure_threshold:
                reasons.append(f"{ip_fails} failed login attempts (exceeds threshold of {failure_threshold})")
            if success_after_failures:
                reasons.append("Successful login recorded immediately after consecutive failed attempts")
            if any(u.lower() in SUSPICIOUS_DEFAULT_USERNAMES for u in users_seen):
                targeted_priv = [u for u in users_seen if u.lower() in SUSPICIOUS_DEFAULT_USERNAMES]
                reasons.append(f"Targeted privileged/default accounts: {', '.join(targeted_priv)}")

            if reasons:
                # Determine severity
                if success_after_failures or ip_fails >= failure_threshold * 4:
                    sev = "CRITICAL"
                elif ip_fails >= failure_threshold * 2:
                    sev = "HIGH"
                else:
                    sev = "MEDIUM"

                profile = SuspiciousIPProfile(
                    ip_address=ip,
                    failed_attempts=ip_fails,
                    successful_attempts=ip_successes,
                    targeted_users=users_seen,
                    severity=sev,
                    success_after_failures=success_after_failures,
                    anomaly_reasons=reasons,
                )
                suspicious_ips.append(profile)

                # Generate finding for risk engine
                findings.append(
                    Finding(
                        name=f"Suspicious Authentication Activity from {ip}",
                        category="Authentication Security",
                        severity=Severity(sev),
                        description=(
                            f"Host {ip} generated {ip_fails} authentication failures. "
                            f"Anomalies: {'; '.join(reasons)}."
                        ),
                        recommendation=(
                            f"Investigate host {ip}. Ensure rate limiting and IP filtering are enforced. "
                            f"Verify integrity of accounts: {', '.join(users_seen)}."
                        ),
                        details=profile.to_dict(),
                    )
                )

        if not suspicious_ips and failed_count > 0:
            findings.append(
                Finding(
                    name="Routine Authentication Failures Observed",
                    category="Authentication Security",
                    severity=Severity.LOW,
                    description=f"{failed_count} isolated authentication failures detected, below suspicious thresholds.",
                    recommendation="Monitor logs regularly for emerging patterns.",
                    details={"failed_count": failed_count},
                )
            )

        if not findings:
            findings.append(
                Finding(
                    name="Authentication Logs Clean",
                    category="Authentication Security",
                    severity=Severity.INFO,
                    description="No suspicious authentication anomalies or brute force patterns identified.",
                    recommendation="Maintain log retention and periodic auditing.",
                    details={"events_analyzed": total_events},
                )
            )

        # Sort suspicious IPs by failed attempts descending
        suspicious_ips.sort(key=lambda x: x.failed_attempts, reverse=True)

        return LogAnalysisResult(
            file_path=str(path),
            total_events=total_events,
            failed_logins=failed_count,
            successful_logins=success_count,
            suspicious_ips=suspicious_ips,
            targeted_privileged_accounts=sorted(list(privileged_targeted)),
            findings=findings,
            recommendations=recommendations,
        )

    @classmethod
    def format_terminal_report(cls, result: LogAnalysisResult) -> str:
        """Formats log analysis output into clean terminal report."""
        lines: List[str] = [
            "Security Log Analysis",
            "=====================",
            f"Log File: {result.file_path}",
            f"Total events: {result.total_events}",
            f"Failed logins: {result.failed_logins}",
            f"Successful logins: {result.successful_logins}",
            "",
            "Suspicious IPs:",
            "-" * 45,
        ]

        if result.suspicious_ips:
            for ip in result.suspicious_ips:
                lines.extend([
                    f"\nIP: {ip.ip_address}",
                    f"Failed attempts: {ip.failed_attempts}",
                    f"Successful attempts: {ip.successful_attempts}",
                    f"Severity: {ip.severity}",
                    f"Targeted users: {', '.join(ip.targeted_users)}",
                ])
                if ip.success_after_failures:
                    lines.append("⚠️  ALERT: Successful login after multiple failed attempts (possible compromise)!")
                for r in ip.anomaly_reasons:
                    lines.append(f"  - {r}")
        else:
            lines.append("No suspicious IP addresses exceeded attack thresholds.")

        if result.targeted_privileged_accounts:
            lines.extend([
                "",
                f"Targeted Privileged Accounts: {', '.join(result.targeted_privileged_accounts)}",
            ])

        lines.extend([
            "",
            "-" * 45,
            "Recommendations:",
        ])
        for rec in result.recommendations:
            lines.append(f"- {rec}")

        return "\n".join(lines)
