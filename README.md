# CyberGuard - Lightweight Cybersecurity Assessment Toolkit

[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-37%20passed-brightgreen.svg)](tests/)
[![Security: Defensive](https://img.shields.io/badge/security-defensive%20only-green.svg)](SECURITY.md)

**CyberGuard** is a modular, zero-bloat Python defensive cybersecurity assessment toolkit designed for systems administrators, security auditors, students, and DevOps engineers. It provides automated defensive auditing capabilities across network attack surface discovery, credential entropy verification, cryptographic file integrity monitoring, and authentication anomaly log detection.

Built entirely on the **Python standard library** for its core assessment runtime, CyberGuard delivers enterprise-grade defensive security evaluation without requiring heavy third-party runtime dependencies.

---

## Features

- **🌐 Network Port Scanning:**
  - Multi-threaded TCP connect port scanner with configurable thread pools (`ThreadPoolExecutor`).
  - Strict RFC 1123 hostname and IPv4/IPv6 address validation.
  - Flexible port selectors: range syntax (`1-1024`), discrete lists (`22,80,443`), or curated presets (`common`).
  - Automatic service identification with security baseline risk classification.
  - Strict pre-execution authorization warning banners.

- **🔑 Password Security Analysis & Generation:**
  - Shannon entropy and NIST character pool entropy calculation ($E = L \times \log_2(R)$).
  - Multi-class character diversity checks (uppercase, lowercase, numbers, symbols).
  - Pattern heuristics: detects consecutive identical characters and sequential keyboard runs (`qwerty`, `123456`).
  - Educational weak dictionary matching against universally targeted credentials.
  - Explainable 0–100 security scoring rubric with actionable remediation advice.
  - Cryptographically secure password and Diceware-style passphrase generator (`secrets` module).
  - **Zero Credential Retention:** Passwords are never transmitted, persisted, or logged.

- **#️⃣ Cryptographic Hashing & Verification:**
  - Supported algorithms: **SHA-256**, **SHA-512**, **SHA-1**, and **MD5** (with explicit cryptographic deprecation warnings).
  - Memory-efficient chunked streaming file hashing for files of any size.
  - Timing-attack resistant constant-time verification using `hmac.compare_digest`.
  - Batch digest calculations for cross-algorithm comparison.

- **🛡️ File Integrity Monitoring (FIM):**
  - Snapshot cryptographic baseline manifest generation across directory trees.
  - Differential change detection: instantly identifies **modified**, **added**, and **deleted** files.
  - Exportable JSON baseline manifests for scheduled configuration audits.

- **📜 Security Log Analysis:**
  - Ingestion and parsing of structured logs and standard Linux syslog / OpenSSH `auth.log`.
  - Automated detection of brute-force attacks exceeding configurable thresholds.
  - Anomaly detection: flags successful logins that immediately succeed repeated failures (potential credential compromise).
  - Privileged and default account targeting surveillance (`root`, `admin`, `administrator`, `guest`).

- **⚖️ Transparent Risk Scoring Engine:**
  - Standardized findings schema: Category, Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), Description, and Recommendation.
  - Explainable 0–100 overall security posture score based on accumulated findings.

- **📊 Multi-Format Security Reporting:**
  - ANSI-formatted terminal executive summaries.
  - Machine-readable JSON reports for SIEM and CI/CD pipelines.
  - Self-contained, responsive modern HTML security reports.

---

## Architecture

```
CyberGuard/
│
├── core/                                # Foundational engines & security logic
│   ├── __init__.py
│   ├── scanner.py                       # Network TCP connect & thread pool engine
│   ├── hashing.py                       # Streaming cryptographic hashing & safe comparison
│   ├── password_analyzer.py             # Entropy calculator & cryptographic generator
│   ├── logger.py                        # Secure logging with credential redaction filter
│   └── risk_engine.py                   # Transparent 0-100 risk scoring & findings engine
│
├── modules/                             # High-level assessment modules
│   ├── __init__.py
│   ├── port_scanner.py                  # Port scanner CLI module & formatter
│   ├── password_checker.py              # Password analysis & recommendation module
│   ├── hash_analyzer.py                 # Hash verification & multi-digest module
│   ├── file_integrity.py                # FIM baseline & differential diff module
│   └── log_analyzer.py                  # Authentication log & brute-force parser
│
├── reports/                             # Reporting subsystem
│   ├── __init__.py
│   └── report_generator.py              # Terminal, JSON, and HTML report compilers
│
├── tests/                               # Comprehensive deterministic unit tests
│   ├── __init__.py
│   ├── test_port_scanner.py
│   ├── test_password_checker.py
│   ├── test_hashing.py
│   ├── test_file_integrity.py
│   ├── test_log_analyzer.py
│   ├── test_risk_engine.py
│   └── test_report_generator.py
│
├── samples/                             # Educational test artifacts
│   ├── sample_auth.log                  # Sample security authentication event log
│   └── sample_config.txt                # Sample server configuration file
│
├── legacy/                              # Preserved original educational scripts
│   ├── README_ORIGINAL.md
│   ├── caesar_cipher.py
│   ├── hash_generator.py
│   ├── password_strength_checker.py
│   └── port_scanner.py
│
├── reports_output/                      # Destination directory for generated reports
├── logs/                                # Application audit logs (cyberguard.log)
├── main.py                              # Unified CLI entry point
├── config.py                            # Central settings & protocol catalogs
├── requirements.txt                     # Development and test dependencies
├── pyproject.toml                       # Build and packaging configuration
├── .gitignore                           # Git ignore rules
├── SECURITY.md                          # Vulnerability reporting & ethical policies
└── LICENSE                              # MIT License & attribution
```

---

## Installation

### Prerequisites
- Python 3.9 or higher (tested up to Python 3.14).

### Clone & Setup

```bash
# 1. Clone repository
git clone https://github.com/the-evilyn/CyberGuard-Lightweight-Cybersecurity-Assessment-Toolkit.git
cd CyberGuard-Lightweight-Cybersecurity-Assessment-Toolkit

# 2. Create virtual environment
python3 -m venv .venv

# 3. Activate virtual environment
# On Linux / macOS:
source .venv/bin/activate
# On Windows:
# .venv\Scripts\activate

# 4. Install test dependencies
pip install -r requirements.txt
```

> **Note:** The core CyberGuard assessment engine relies exclusively on the standard library. `pytest` is only required for running the automated test suite.

---

## Usage

CyberGuard provides an intuitive sub-command interface via `main.py`:

```bash
python main.py --help
```

### 1. Network Port Scanning

> **Notice:** Only scan systems you own or have explicit written permission to test.

```bash
# Scan common defensive ports on localhost
python main.py scan --target 127.0.0.1 --ports common

# Scan a custom port range with custom timeout and workers
python main.py scan --target 192.168.1.1 --ports 1-1024 --timeout 0.5 --workers 100

# Export scan results directly to an HTML report
python main.py scan --target 127.0.0.1 --ports 22,80,443 --output reports_output/scan_report.html
```

### 2. Password Security Analysis & Generation

```bash
# Evaluate a password with secure hidden terminal input (no echo)
python main.py password

# Evaluate a specific password directly
python main.py password --password "P@ssw0rd123!"

# Generate a 18-character cryptographically secure random password
python main.py password --generate --length 18

# Generate a 4-word Diceware-style passphrase
python main.py password --passphrase --words 4 --separator "-"
```

### 3. Cryptographic Hashing & Verification

```bash
# Calculate all supported hashes for a string
python main.py hash --text "CyberGuardSecurity2026" --all

# Calculate SHA-256 hash of a file
python main.py hash --file samples/sample_config.txt --algo sha256

# Verify a file's integrity against an expected hash
python main.py hash --file samples/sample_config.txt --algo sha256 --verify 8b6a24fd1b4f423f71a2503ff01f93d55eab7934f388da8237441b1f4c14b7bb

# Constant-time comparison between two hash digests
python main.py hash --compare e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 --hash2 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 4. File Integrity Monitoring (FIM)

```bash
# Step 1: Create an initial cryptographic baseline manifest
python main.py integrity --create-baseline --path ./samples --manifest ./samples/sample_baseline.json

# Step 2: Verify filesystem integrity against baseline
python main.py integrity --verify-baseline --path ./samples --manifest ./samples/sample_baseline.json
```

### 5. Security Log Analysis

```bash
# Analyze sample authentication log with default thresholds
python main.py logs --file ./samples/sample_auth.log

# Analyze with custom failure threshold and export to JSON
python main.py logs --file ./samples/sample_auth.log --threshold 3 --output reports_output/log_report.json
```

### 6. Security Assessment Reports

```bash
# Generate Terminal assessment report
python main.py report --target "Perimeter Audit" --format terminal

# Generate machine-readable JSON report
python main.py report --target "Perimeter Audit" --format json --output reports_output/audit.json

# Generate modern standalone HTML report
python main.py report --target "Perimeter Audit" --format html --output reports_output/audit.html
```

---

## Example Output

### Network Scan
```
CyberGuard Network Scanner
===========================
Target: 192.168.1.10 (192.168.1.10)
Ports Scanned: 1024

PORT     STATE     SERVICE        RISK      
---------------------------------------------
22       OPEN      SSH            INFO      
80       OPEN      HTTP           LOW       
443      OPEN      HTTPS          INFO      
---------------------------------------------
Scan completed in 1.45 seconds.
Open Ports: 3

Security observations:
- Port 22 (SSH) is OPEN - Encrypted remote administrative shell (verify authentication & key strength).
- Port 80 (HTTP) is OPEN - Unencrypted web server (recommend TLS redirection to HTTPS).
- Port 443 (HTTPS) is OPEN - Encrypted TLS web communications.
```

### Password Security Analysis
```
Password Security Analysis
===========================
Score: 82/100
Risk: LOW

Length: 14
Character diversity: GOOD (3/4 classes)
Entropy estimate: GOOD (65.8 bits)
Common pattern: NONE

Recommendations:
- Include special characters (!@#$%^&*).
- Excellent password complexity. Follow regular rotation and use a password manager.
```

### Security Log Analysis
```
Security Log Analysis
=====================
Log File: /projects/CyberGuard/samples/sample_auth.log
Total events: 48
Failed logins: 43
Successful logins: 5

Suspicious IPs:
---------------------------------------------

IP: 10.0.0.23
Failed attempts: 31
Successful attempts: 1
Severity: CRITICAL
Targeted users: administrator
⚠️  ALERT: Successful login after multiple failed attempts (possible compromise)!
  - 31 failed login attempts (exceeds threshold of 5)
  - Successful login recorded immediately after consecutive failed attempts
  - Targeted privileged/default accounts: administrator

IP: 192.168.1.50
Failed attempts: 12
Successful attempts: 0
Severity: HIGH
Targeted users: admin, backup, guest, oracle, root, test
  - 12 failed login attempts (exceeds threshold of 5)
  - Targeted privileged/default accounts: admin, backup, guest, oracle, root, test

Targeted Privileged Accounts: admin, administrator, backup, guest, oracle, root, test
---------------------------------------------
Recommendations:
- Review authentication logs for repeated failed logins.
- Enforce rate limiting and account lockout policies for authentication endpoints.
- Implement multi-factor authentication (MFA) across all administrative services.
```

---

## Security Considerations

1. **Explicit Authorization:** Network scanning functionality must strictly be directed at hosts and subnets you own or have explicit written permission to assess. Unauthorized scanning may violate computer misuse laws.
2. **Defensive and Educational Scope:** CyberGuard is designed exclusively for defense, posture auditing, and learning. It does not perform offensive exploitation, evasion, or destructive operations.
3. **Password Privacy:** Passwords evaluated by CyberGuard are processed in volatile memory only and are never saved to disk, transmitted over external networks, or printed in application logs.
4. **MD5 & SHA-1 Deprecation:** Support for MD5 and SHA-1 is maintained for legacy checksum verification and educational demonstration. The toolkit automatically displays advisory warnings recommending SHA-256 or SHA-512 for modern security integrity.

For vulnerability disclosure guidelines, review our [SECURITY.md](SECURITY.md).

---

## Testing

The project includes an automated, deterministic test suite verifying all modules without requiring external network connectivity:

```bash
# Run all tests via pytest
pytest

# Run tests with verbose output
pytest -v
```

All 37 unit tests across port scanning, password entropy, cryptographic hashing, file integrity diffs, log parsing, risk scoring, and report generation execute in under 2 seconds.

---

## Roadmap

- [ ] **Interactive Web Dashboard:** Lightweight local web UI for visual inspection of historical scans and logs.
- [ ] **Persistent SQLite Storage:** Database backend to track asset risk posture trends over time.
- [ ] **Expanded Log Format Adapters:** Ingestion parsers for Windows Security Event Logs (`EVTX`), Suricata/Snort EVE JSON, and AWS CloudTrail logs.
- [ ] **Known Vulnerability (CVE) Mapping:** Passive banner correlation with public CVE databases.
- [ ] **Containerization & CI/CD Integration:** Official Dockerfile and GitHub Actions security audit workflows.

---

## License & Attribution

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

- **Original Base Project:** [cybersecurity-beginner-project](https://github.com/karansoni15-create/cybersecurity-beginner-project) by [karansoni15-create](https://github.com/karansoni15-create).
- **Refactoring & Architectural Redesign:** Enhanced and expanded into **CyberGuard** by [the-evilyn](https://github.com/the-evilyn).
