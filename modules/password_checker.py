"""
CyberGuard Password Checker Module.

Provides user-facing interface for password security analysis,
safe terminal formatting, and cryptographically secure credential generation.
"""

from typing import List, Optional

from core.logger import get_logger
from core.password_analyzer import PasswordAnalysisResult, PasswordAnalyzer
from core.risk_engine import Finding, Severity

logger = get_logger("modules.password_checker")


class PasswordCheckerModule:
    """User-facing password assessment module."""

    @classmethod
    def analyze(cls, password: str) -> PasswordAnalysisResult:
        """Evaluates password complexity and returns structured metrics."""
        return PasswordAnalyzer.analyze(password)

    @classmethod
    def generate_password(cls, length: int = 16) -> str:
        """Generates a high-entropy random password."""
        return PasswordAnalyzer.generate_secure_password(length=length)

    @classmethod
    def generate_passphrase(cls, words: int = 4, separator: str = "-") -> str:
        """Generates a secure multi-word passphrase."""
        return PasswordAnalyzer.generate_passphrase(words_count=words, separator=separator)

    @classmethod
    def convert_to_findings(cls, result: PasswordAnalysisResult) -> List[Finding]:
        """Translates password evaluation diagnostics into risk engine findings."""
        findings: List[Finding] = []

        if result.score < 50:
            sev = Severity.CRITICAL if result.score < 30 else Severity.HIGH
            findings.append(
                Finding(
                    name="Weak Credential Policy Violation",
                    category="Credential Security",
                    severity=sev,
                    description=(
                        f"Evaluated password received a security score of {result.score}/100 "
                        f"with {result.risk_level} risk level."
                    ),
                    recommendation="Adopt a minimum 16-character passphrase and avoid dictionary terms.",
                    details=result.to_dict(),
                )
            )
        elif result.score < 75:
            findings.append(
                Finding(
                    name="Moderate Password Complexity",
                    category="Credential Security",
                    severity=Severity.MEDIUM,
                    description=f"Evaluated password scored {result.score}/100.",
                    recommendation="Increase password length or character diversity.",
                    details=result.to_dict(),
                )
            )
        elif result.score < 90:
            findings.append(
                Finding(
                    name="Adequate Password Complexity",
                    category="Credential Security",
                    severity=Severity.LOW,
                    description=f"Evaluated password scored {result.score}/100.",
                    recommendation="Ensure password is not reused across multiple services.",
                    details=result.to_dict(),
                )
            )
        else:
            findings.append(
                Finding(
                    name="Strong Password Posture",
                    category="Credential Security",
                    severity=Severity.INFO,
                    description=f"Evaluated password received optimal score {result.score}/100.",
                    recommendation="Continue using unique credentials with a password manager.",
                    details=result.to_dict(),
                )
            )

        return findings

    @classmethod
    def format_terminal_report(cls, result: PasswordAnalysisResult) -> str:
        """Formats the analysis result into a clean terminal report."""
        diversity_label = "POOR"
        if result.diversity_count == 4:
            diversity_label = "EXCELLENT"
        elif result.diversity_count == 3:
            diversity_label = "GOOD"
        elif result.diversity_count == 2:
            diversity_label = "MODERATE"

        entropy_label = "WEAK"
        if result.nist_entropy_bits >= 80:
            entropy_label = "VERY STRONG"
        elif result.nist_entropy_bits >= 60:
            entropy_label = "GOOD"
        elif result.nist_entropy_bits >= 40:
            entropy_label = "MODERATE"

        pattern_summary = "NONE"
        if result.identified_patterns:
            pattern_summary = ", ".join(result.identified_patterns)

        lines: List[str] = [
            "Password Security Analysis",
            "===========================",
            f"Score: {result.score}/100",
            f"Risk: {result.risk_level}",
            "",
            f"Length: {result.length}",
            f"Character diversity: {diversity_label} ({result.diversity_count}/4 classes)",
            f"Entropy estimate: {entropy_label} ({result.nist_entropy_bits:.1f} bits)",
            f"Common pattern: {pattern_summary}",
            "",
            "Recommendations:",
        ]

        for rec in result.recommendations:
            lines.append(f"- {rec}")

        return "\n".join(lines)
