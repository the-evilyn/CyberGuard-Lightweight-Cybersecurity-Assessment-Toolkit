# Security Policy

## Responsible Disclosure

Security is fundamental to the **CyberGuard** project. If you discover a vulnerability or security flaw within this toolkit or its modules, please help us protect our users by disclosing it responsibly.

### Reporting a Vulnerability

- **Do NOT** report security vulnerabilities via public GitHub issues.
- Please report vulnerabilities privately by emailing: `salmaev646@gmail.com`
- Include a detailed summary of the vulnerability, reproduction steps, affected versions, and potential impact.
- We will acknowledge receipt of your vulnerability report within 48 hours and provide an estimated timeline for remediation.

## Educational and Defensive Scope

CyberGuard is explicitly designed as a **defensive security assessment toolkit** for educational and authorized operational audits:

1. **Authorization Required:**
   - Network port scanning and assessment features must strictly be executed against hosts, systems, and networks you own or have explicit written authorization to evaluate.
   - Unauthorized network scanning or reconnaissance may violate computer crime laws (such as the Computer Fraud and Abuse Act in the US, Section 1 of the Computer Misuse Act in the UK, or international equivalents).

2. **No Offensive or Malicious Features:**
   - CyberGuard contains no exploit code, weaponized payloads, stealth evasion techniques, rootkits, credential harvesters, or persistence mechanisms.
   - We will reject any pull requests or contributions that introduce malware, denial-of-service, or unauthorized exploitation functionality.

3. **Privacy and Credential Protection:**
   - The password analyzer runs completely locally. Passwords are never sent to external servers or logged in plain text.
   - Any sensitive input handled by the toolkit is excluded from log files by the centralized logging sanitizer.
