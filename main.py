#!/usr/bin/env python3
"""
CyberGuard - Lightweight Cybersecurity Assessment Toolkit.

Main CLI entry point providing defensive security auditing utilities:
- Network TCP port scanning with service identification
- Password security analysis and cryptographic generation
- Cryptographic hashing and verification (SHA-256, SHA-512, SHA-1, MD5)
- File integrity baseline monitoring and diff detection
- Security authentication log anomaly analysis
- Multi-format executive security assessment reporting
"""

import argparse
import getpass
from pathlib import Path
import sys
from typing import List, Optional

from config import (
    APP_NAME,
    APP_SUBTITLE,
    DEFAULT_BRUTE_FORCE_THRESHOLD,
    DEFAULT_HASH_ALGORITHM,
    DEFAULT_MAX_WORKERS,
    DEFAULT_PORT_RANGE,
    DEFAULT_SCAN_TIMEOUT,
    REPORTS_DIR,
    VERSION,
)
from core.logger import get_logger, setup_logging
from core.risk_engine import RiskEngine
from modules.file_integrity import FileIntegrityMonitor
from modules.hash_analyzer import HashAnalyzerModule
from modules.log_analyzer import SecurityLogAnalyzer
from modules.password_checker import PasswordCheckerModule
from modules.port_scanner import PortScannerModule
from reports.report_generator import ReportGenerator

logger = get_logger("cli")


def handle_scan(args: argparse.Namespace) -> int:
    """Handles the network port scanning command."""
    target = args.target
    ports = args.ports
    timeout = args.timeout
    workers = args.workers

    try:
        summary = PortScannerModule.scan(
            target=target,
            port_spec=ports,
            timeout=timeout,
            max_workers=workers,
            display_warning=not args.quiet,
        )
        print(PortScannerModule.format_terminal_report(summary))

        if args.output:
            rep = ReportGenerator(target=target, findings=summary.findings)
            out_path = Path(args.output)
            if out_path.suffix.lower() == ".json":
                rep.generate_json_report(out_path)
            elif out_path.suffix.lower() == ".html":
                rep.generate_html_report(out_path)
            else:
                out_path.write_text(PortScannerModule.format_terminal_report(summary), encoding="utf-8")
            print(f"\n[+] Scan report written to {out_path}")

        return 0
    except Exception as exc:
        print(f"[-] Scan failed: {exc}", file=sys.stderr)
        logger.error("Scan error on %s: %s", target, exc)
        return 1


def handle_password(args: argparse.Namespace) -> int:
    """Handles password analysis and generation commands."""
    try:
        if args.generate:
            pwd = PasswordCheckerModule.generate_password(length=args.length)
            print("\n🔐 Generated Cryptographically Secure Password:")
            print("=" * 50)
            print(f"Password : {pwd}")
            print(f"Length   : {len(pwd)}")
            print("=" * 50)
            return 0

        if args.passphrase:
            phrase = PasswordCheckerModule.generate_passphrase(words=args.words, separator=args.separator)
            print("\n🔐 Generated Cryptographically Secure Passphrase:")
            print("=" * 50)
            print(f"Passphrase : {phrase}")
            print(f"Word count : {args.words}")
            print("=" * 50)
            return 0

        target_password = args.password
        if not target_password:
            # Secure interactive input without terminal echoing
            target_password = getpass.getpass("Enter password to evaluate (input hidden): ")

        if not target_password:
            print("[-] Error: Empty password provided.", file=sys.stderr)
            return 1

        result = PasswordCheckerModule.analyze(target_password)
        print("\n" + PasswordCheckerModule.format_terminal_report(result))
        return 0
    except Exception as exc:
        print(f"[-] Password evaluation error: {exc}", file=sys.stderr)
        logger.error("Password analysis failed: %s", exc)
        return 1


def handle_hash(args: argparse.Namespace) -> int:
    """Handles text and file cryptographic hashing and verification."""
    algo = args.algo.lower()

    try:
        if args.compare:
            if not args.hash2:
                print("[-] Error: --compare requires two hash arguments (--compare <hash1> --hash2 <hash2>)", file=sys.stderr)
                return 1
            is_match = HashAnalyzerModule.compare(args.compare, args.hash2)
            if is_match:
                print("\n✅ Hashes MATCH (constant-time verification confirmed).")
                return 0
            else:
                print("\n❌ Hashes DO NOT MATCH (differing digests).")
                return 1

        if args.file:
            path = Path(args.file)
            if not path.is_file():
                print(f"[-] Error: File not found: {path}", file=sys.stderr)
                return 1

            if args.all:
                hashes = HashAnalyzerModule.hash_all(path, is_file=True)
                print("\n" + HashAnalyzerModule.format_all_hashes_report(path.name, hashes, is_file=True))
                return 0

            if args.verify:
                is_match, calc_digest, warning = HashAnalyzerModule.verify(
                    data=path, expected_hash=args.verify, algorithm=algo, is_file=True
                )
                print(f"\nFile: {path.name}")
                print(f"Algorithm: {algo.upper()}")
                print(f"Calculated: {calc_digest}")
                print(f"Expected  : {args.verify}")
                if warning:
                    print(f"\n⚠️  {warning}")
                if is_match:
                    print("\n✅ INTEGRITY VERIFIED - File matches expected hash.")
                    return 0
                else:
                    print("\n❌ INTEGRITY TAMPERED - File does not match expected hash!")
                    return 1

            digest, warning = HashAnalyzerModule.hash_file(path, algorithm=algo)
            print(f"\nFile: {path.name}")
            print(f"{algo.upper()} Digest: {digest}")
            if warning:
                print(f"⚠️  {warning}")
            return 0

        if args.text is not None:
            if args.all:
                hashes = HashAnalyzerModule.hash_all(args.text, is_file=False)
                print("\n" + HashAnalyzerModule.format_all_hashes_report(f"'{args.text[:12]}...'", hashes, is_file=False))
                return 0

            if args.verify:
                is_match, calc_digest, warning = HashAnalyzerModule.verify(
                    data=args.text, expected_hash=args.verify, algorithm=algo, is_file=False
                )
                print(f"Calculated: {calc_digest}")
                print(f"Expected  : {args.verify}")
                if warning:
                    print(f"⚠️  {warning}")
                if is_match:
                    print("\n✅ Hash matches.")
                    return 0
                else:
                    print("\n❌ Hash does not match.")
                    return 1

            digest, warning = HashAnalyzerModule.hash_text(args.text, algorithm=algo)
            print(f"{algo.upper()}: {digest}")
            if warning:
                print(f"⚠️  {warning}")
            return 0

        print("[-] Error: Specify --file <path> or --text <string> or --compare <hash>", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[-] Hashing error: {exc}", file=sys.stderr)
        return 1


def handle_integrity(args: argparse.Namespace) -> int:
    """Handles file integrity baseline generation and validation."""
    try:
        if args.create_baseline:
            target_path = Path(args.path or ".")
            manifest_path = Path(args.manifest or (target_path / ".cyberguard_baseline.json"))
            manifest = FileIntegrityMonitor.create_baseline(
                target_path=target_path,
                algorithm=args.algo,
                manifest_save_path=manifest_path,
            )
            print(f"\n[+] Created baseline for {manifest.root_path}")
            print(f"[+] Recorded {len(manifest.files)} files using {manifest.algorithm.upper()}")
            print(f"[+] Saved baseline manifest to: {manifest_path}")
            return 0

        if args.verify_baseline:
            manifest_path = Path(args.manifest or ".cyberguard_baseline.json")
            if not manifest_path.is_file():
                print(f"[-] Error: Baseline manifest not found: {manifest_path}", file=sys.stderr)
                return 1

            target_path = Path(args.path) if args.path else None
            result = FileIntegrityMonitor.verify_against_baseline(
                manifest_or_path=manifest_path,
                target_path=target_path,
            )
            print("\n" + FileIntegrityMonitor.format_terminal_report(result))
            return 0 if result.is_intact else 2

        print("[-] Error: Specify either --create-baseline or --verify-baseline", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[-] File integrity error: {exc}", file=sys.stderr)
        return 1


def handle_logs(args: argparse.Namespace) -> int:
    """Handles security log parsing and brute-force detection."""
    try:
        path = Path(args.file)
        if not path.is_file():
            print(f"[-] Error: Log file not found: {path}", file=sys.stderr)
            return 1

        result = SecurityLogAnalyzer.analyze_file(
            file_path=path,
            failure_threshold=args.threshold,
        )
        print("\n" + SecurityLogAnalyzer.format_terminal_report(result))

        if args.output:
            rep = ReportGenerator(target=f"Log: {path.name}", findings=result.findings)
            out_path = Path(args.output)
            if out_path.suffix.lower() == ".json":
                rep.generate_json_report(out_path)
            elif out_path.suffix.lower() == ".html":
                rep.generate_html_report(out_path)
            else:
                out_path.write_text(SecurityLogAnalyzer.format_terminal_report(result), encoding="utf-8")
            print(f"\n[+] Log assessment report written to {out_path}")

        return 0
    except Exception as exc:
        print(f"[-] Log analyzer error: {exc}", file=sys.stderr)
        return 1


def handle_report(args: argparse.Namespace) -> int:
    """Generates an executive assessment report combining sample or live audit findings."""
    try:
        engine = RiskEngine()

        # If sample evaluation requested, run simulated assessment against samples
        sample_log = Path(__file__).resolve().parent / "samples" / "sample_auth.log"
        if sample_log.is_file():
            log_res = SecurityLogAnalyzer.analyze_file(sample_log)
            engine.add_findings(log_res.findings)

        report_gen = ReportGenerator(target=args.target or "Local Security Audit", risk_engine=engine)

        if args.format == "json":
            out_file = args.output or (REPORTS_DIR / "security_report.json")
            json_data = report_gen.generate_json_report(output_file=out_file)
            print(json_data)
            print(f"\n[+] JSON report saved to: {out_file}")
        elif args.format == "html":
            out_file = args.output or (REPORTS_DIR / "security_report.html")
            report_gen.generate_html_report(output_file=out_file)
            print(f"\n[+] Modern HTML assessment report generated at: {out_file}")
        else:
            print("\n" + report_gen.generate_terminal_report())
            if args.output:
                Path(args.output).write_text(report_gen.generate_terminal_report(), encoding="utf-8")
                print(f"\n[+] Report saved to: {args.output}")

        return 0
    except Exception as exc:
        print(f"[-] Report generation error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Constructs the top-level argument parser and subcommands."""
    parser = argparse.ArgumentParser(
        prog="cyberguard",
        description=f"{APP_NAME} v{VERSION} - {APP_SUBTITLE}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--version", action="version", version=f"{APP_NAME} v{VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")

    subparsers = parser.add_subparsers(dest="command", help="Available assessment commands")

    # 1. SCAN
    scan_parser = subparsers.add_parser("scan", help="TCP network port scanner")
    scan_parser.add_argument("--target", "-t", required=True, help="Target IP address or hostname (e.g. 127.0.0.1)")
    scan_parser.add_argument("--ports", "-p", default=DEFAULT_PORT_RANGE, help=f"Port specification (default: {DEFAULT_PORT_RANGE}, or 'common')")
    scan_parser.add_argument("--timeout", type=float, default=DEFAULT_SCAN_TIMEOUT, help=f"Socket timeout in seconds (default: {DEFAULT_SCAN_TIMEOUT})")
    scan_parser.add_argument("--workers", "-w", type=int, default=DEFAULT_MAX_WORKERS, help=f"Concurrency worker threads (default: {DEFAULT_MAX_WORKERS})")
    scan_parser.add_argument("--output", "-o", help="Save scan output to file (.txt, .json, .html)")
    scan_parser.add_argument("--quiet", action="store_true", help="Suppress the legal authorization warning banner")

    # 2. PASSWORD
    pwd_parser = subparsers.add_parser("password", help="Password security analyzer and secure generator")
    pwd_parser.add_argument("--password", help="Password string to analyze (leave empty for hidden input prompt)")
    pwd_parser.add_argument("--generate", "-g", action="store_true", help="Generate a cryptographically secure random password")
    pwd_parser.add_argument("--length", "-l", type=int, default=16, help="Length for generated password (default: 16)")
    pwd_parser.add_argument("--passphrase", action="store_true", help="Generate a Diceware-style multi-word passphrase")
    pwd_parser.add_argument("--words", type=int, default=4, help="Word count for passphrase (default: 4)")
    pwd_parser.add_argument("--separator", default="-", help="Separator between passphrase words (default: '-')")

    # 3. HASH
    hash_parser = subparsers.add_parser("hash", help="Cryptographic hash generator and verifier")
    hash_parser.add_argument("--file", "-f", help="Target file to hash")
    hash_parser.add_argument("--text", help="Text string to hash")
    hash_parser.add_argument("--algo", "-a", default=DEFAULT_HASH_ALGORITHM, help=f"Hash algorithm (sha256, sha512, sha1, md5; default: {DEFAULT_HASH_ALGORITHM})")
    hash_parser.add_argument("--all", action="store_true", help="Calculate all supported algorithm digests simultaneously")
    hash_parser.add_argument("--verify", help="Expected hash digest to verify against")
    hash_parser.add_argument("--compare", help="First hash digest for constant-time comparison")
    hash_parser.add_argument("--hash2", help="Second hash digest for constant-time comparison")

    # 4. INTEGRITY
    int_parser = subparsers.add_parser("integrity", help="File integrity monitoring (baseline creation and diff validation)")
    int_parser.add_argument("--create-baseline", action="store_true", help="Generate and save a baseline manifest")
    int_parser.add_argument("--verify-baseline", action="store_true", help="Check current filesystem state against baseline")
    int_parser.add_argument("--path", "-p", default=".", help="Target directory or file path (default: current directory)")
    int_parser.add_argument("--manifest", "-m", help="Path to baseline manifest JSON file")
    int_parser.add_argument("--algo", "-a", default=DEFAULT_HASH_ALGORITHM, help=f"Algorithm for baseline checksums (default: {DEFAULT_HASH_ALGORITHM})")

    # 5. LOGS
    log_parser = subparsers.add_parser("logs", help="Security authentication log analyzer")
    log_parser.add_argument("--file", "-f", required=True, help="Path to authentication log file (e.g. auth.log)")
    log_parser.add_argument("--threshold", type=int, default=DEFAULT_BRUTE_FORCE_THRESHOLD, help=f"Failed attempts threshold for alerts (default: {DEFAULT_BRUTE_FORCE_THRESHOLD})")
    log_parser.add_argument("--output", "-o", help="Save log analysis report to file (.txt, .json, .html)")

    # 6. REPORT
    rep_parser = subparsers.add_parser("report", help="Generate multi-format executive assessment report")
    rep_parser.add_argument("--target", default="Defensive Audit", help="Assessment target label")
    rep_parser.add_argument("--format", choices=["terminal", "json", "html"], default="terminal", help="Report format (default: terminal)")
    rep_parser.add_argument("--output", "-o", help="Output file destination for report")

    return parser


def main() -> None:
    """Main application execution router."""
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    setup_logging(enable_console=args.verbose)

    dispatch = {
        "scan": handle_scan,
        "password": handle_password,
        "hash": handle_hash,
        "integrity": handle_integrity,
        "logs": handle_logs,
        "report": handle_report,
    }

    handler = dispatch.get(args.command)
    if handler:
        exit_code = handler(args)
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
