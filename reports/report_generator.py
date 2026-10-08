"""
CyberGuard Unified Security Assessment Report Generator.

Compiles findings and evaluations from multiple assessment modules into
professional Terminal, JSON, and HTML reports.
"""

from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from config import APP_NAME, APP_SUBTITLE, REPORTS_DIR, VERSION
from core.logger import get_logger
from core.risk_engine import Finding, RiskEngine

logger = get_logger("reports.report_generator")


class ReportGenerator:
    """Orchestrates multi-format security assessment report compilation."""

    def __init__(
        self,
        target: str = "Local Environment",
        findings: Optional[List[Finding]] = None,
        risk_engine: Optional[RiskEngine] = None,
    ) -> None:
        self.target: str = target
        self.risk_engine: RiskEngine = risk_engine or RiskEngine()
        if findings:
            self.risk_engine.add_findings(findings)

    def add_findings(self, findings: List[Finding]) -> None:
        """Appends additional findings to the report engine."""
        self.risk_engine.add_findings(findings)

    def generate_terminal_report(self) -> str:
        """Renders an ANSI-compatible formatted terminal report."""
        summary = self.risk_engine.get_summary()
        findings = self.risk_engine.findings

        lines: List[str] = [
            f"{APP_NAME} Security Assessment",
            "=" * 45,
            f"Target: {self.target}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Overall Score: {summary.overall_score}/100 ({summary.risk_level})",
            "",
            "Findings Summary:",
            f"  CRITICAL: {summary.critical_count} | HIGH: {summary.high_count} | MEDIUM: {summary.medium_count} | LOW: {summary.low_count} | INFO: {summary.info_count}",
            "",
            "Detailed Findings:",
            "-" * 60,
            f"{'SEVERITY':<10} {'CATEGORY':<18} {'FINDING'}",
            "-" * 60,
        ]

        if findings:
            for f in findings:
                lines.append(f"{f.severity.value:<10} {f.category[:17]:<18} {f.name}")
        else:
            lines.append("No security vulnerabilities or exposures detected.")

        lines.extend([
            "-" * 60,
            "",
            "Key Recommendations:",
            "-" * 60,
        ])

        seen_recs = set()
        rec_idx = 1
        for f in findings:
            if f.recommendation and f.recommendation not in seen_recs:
                seen_recs.add(f.recommendation)
                lines.append(f"{rec_idx}. {f.recommendation}")
                rec_idx += 1

        if not seen_recs:
            lines.append("1. Maintain current defensive hygiene and periodic security audits.")

        return "\n".join(lines)

    def generate_json_report(self, output_file: Optional[Union[str, Path]] = None) -> str:
        """
        Builds a comprehensive machine-readable JSON security assessment report.
        Optionally writes to disk.
        """
        summary = self.risk_engine.get_summary()
        data = {
            "metadata": {
                "application": APP_NAME,
                "version": VERSION,
                "subtitle": APP_SUBTITLE,
                "target": self.target,
                "generated_at": datetime.now().isoformat(),
            },
            "assessment": {
                "overall_score": summary.overall_score,
                "risk_level": summary.risk_level,
                "total_findings": summary.findings_count,
                "severity_breakdown": {
                    "critical": summary.critical_count,
                    "high": summary.high_count,
                    "medium": summary.medium_count,
                    "low": summary.low_count,
                    "info": summary.info_count,
                },
            },
            "findings": [f.to_dict() for f in self.risk_engine.findings],
        }

        json_str = json.dumps(data, indent=2)

        if output_file:
            path = Path(output_file).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(json_str)
            logger.info("JSON security report written to %s", path)

        return json_str

    def generate_html_report(self, output_file: Optional[Union[str, Path]] = None) -> str:
        """
        Builds a modern, standalone HTML report with embedded responsive styling.
        Optionally writes to disk.
        """
        summary = self.risk_engine.get_summary()
        findings = self.risk_engine.findings

        # Score color mapping
        if summary.overall_score >= 85:
            score_color = "#22c55e"  # green
        elif summary.overall_score >= 70:
            score_color = "#3b82f6"  # blue
        elif summary.overall_score >= 50:
            score_color = "#eab308"  # yellow
        elif summary.overall_score >= 30:
            score_color = "#f97316"  # orange
        else:
            score_color = "#ef4444"  # red

        findings_rows = ""
        for f in findings:
            sev_badge_color = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6",
                "INFO": "#64748b",
            }.get(f.severity.value, "#64748b")

            findings_rows += f"""
            <tr>
                <td><span class="badge" style="background-color: {sev_badge_color};">{f.severity.value}</span></td>
                <td><strong>{f.name}</strong><br><small style="color: #64748b;">{f.description}</small></td>
                <td>{f.category}</td>
                <td>{f.recommendation}</td>
            </tr>
            """

        if not findings_rows:
            findings_rows = """<tr><td colspan="4" style="text-align: center; color: #22c55e; padding: 24px;">No vulnerabilities or security issues identified.</td></tr>"""

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{APP_NAME} Security Assessment Report - {self.target}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{ margin: 0; font-size: 1.8rem; color: var(--accent); }}
        .meta {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.3rem; }}
        .score-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-around;
            margin-bottom: 2rem;
        }}
        .score-circle {{
            font-size: 2.8rem;
            font-weight: 800;
            color: {score_color};
        }}
        .stats {{
            display: flex;
            gap: 1.5rem;
        }}
        .stat-item {{
            text-align: center;
        }}
        .stat-val {{ font-size: 1.4rem; font-weight: bold; }}
        .stat-label {{ font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border-radius: 8px;
            overflow: hidden;
            margin-top: 1rem;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #0f172a;
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        .badge {{
            color: #fff;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            display: inline-block;
        }}
        footer {{
            margin-top: 3rem;
            border-top: 1px solid var(--border);
            padding-top: 1rem;
            color: var(--text-muted);
            font-size: 0.8rem;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>{APP_NAME} Security Assessment</h1>
                <div class="meta">{APP_SUBTITLE} v{VERSION}</div>
                <div class="meta">Target: <strong>{self.target}</strong> | Evaluated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
            </div>
        </header>

        <div class="score-card">
            <div style="text-align: center;">
                <div class="score-circle">{summary.overall_score}/100</div>
                <div style="font-weight: 600; letter-spacing: 1px;">{summary.risk_level}</div>
            </div>
            <div class="stats">
                <div class="stat-item"><div class="stat-val" style="color: #ef4444;">{summary.critical_count}</div><div class="stat-label">Critical</div></div>
                <div class="stat-item"><div class="stat-val" style="color: #f97316;">{summary.high_count}</div><div class="stat-label">High</div></div>
                <div class="stat-item"><div class="stat-val" style="color: #eab308;">{summary.medium_count}</div><div class="stat-label">Medium</div></div>
                <div class="stat-item"><div class="stat-val" style="color: #3b82f6;">{summary.low_count}</div><div class="stat-label">Low</div></div>
                <div class="stat-item"><div class="stat-val" style="color: #64748b;">{summary.info_count}</div><div class="stat-label">Info</div></div>
            </div>
        </div>

        <h2>Security Findings</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 100px;">Severity</th>
                    <th>Finding & Details</th>
                    <th style="width: 140px;">Category</th>
                    <th style="width: 300px;">Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>

        <footer>
            Notice: This report was generated by {APP_NAME} v{VERSION} for authorized defensive audit purposes only.
        </footer>
    </div>
</body>
</html>
"""
        if output_file:
            path = Path(output_file).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_template)
            logger.info("HTML security report written to %s", path)

        return html_template
