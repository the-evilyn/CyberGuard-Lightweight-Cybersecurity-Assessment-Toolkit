"""
CyberGuard Transparent Risk Scoring Engine.

Provides normalized security finding representations, severity classifications,
and an explainable 0-100 security scoring mechanism.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from config import SEVERITY_DEDUCTIONS


class Severity(str, Enum):
    """Normalized security severity levels."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    """Represents an individual security finding or vulnerability observation."""
    name: str
    category: str
    severity: Severity
    description: str
    recommendation: str
    score_deduction: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.upper())
        if self.score_deduction is None:
            self.score_deduction = SEVERITY_DEDUCTIONS.get(self.severity.value, 0)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to standard serializable dictionary."""
        return {
            "name": self.name,
            "category": self.category,
            "severity": self.severity.value,
            "score_deduction": self.score_deduction,
            "description": self.description,
            "recommendation": self.recommendation,
            "details": self.details,
        }


@dataclass
class AssessmentSummary:
    """Summarizes overall risk evaluation metrics."""
    overall_score: int
    risk_level: str
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int


class RiskEngine:
    """
    Transparent defensive security scoring engine.
    Calculates an overall security posture score (0 - 100) based on accumulated findings.
    """

    def __init__(self, base_score: int = 100) -> None:
        self.base_score: int = base_score
        self.findings: List[Finding] = []

    def add_finding(self, finding: Finding) -> None:
        """Register a new security finding."""
        self.findings.append(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        """Register multiple findings."""
        for finding in findings:
            self.add_finding(finding)

    def calculate_score(self) -> int:
        """
        Calculates the net security score.
        Deductions are capped at 0 (minimum possible score is 0, maximum is 100).
        """
        total_deduction = sum(f.score_deduction or 0 for f in self.findings)
        score = max(0, min(100, self.base_score - total_deduction))
        return score

    def determine_risk_level(self, score: int) -> str:
        """Derives a human-readable risk posture rating from the numerical score."""
        if score >= 90:
            return "MINIMAL RISK"
        elif score >= 75:
            return "LOW RISK"
        elif score >= 50:
            return "MEDIUM RISK"
        elif score >= 25:
            return "HIGH RISK"
        else:
            return "CRITICAL RISK"

    def get_summary(self) -> AssessmentSummary:
        """Computes statistical distribution across findings and returns an assessment summary."""
        score = self.calculate_score()
        risk_level = self.determine_risk_level(score)

        critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in self.findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in self.findings if f.severity == Severity.INFO)

        return AssessmentSummary(
            overall_score=score,
            risk_level=risk_level,
            findings_count=len(self.findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes complete engine state to dictionary."""
        summary = self.get_summary()
        return {
            "summary": asdict(summary),
            "findings": [f.to_dict() for f in self.findings],
        }
