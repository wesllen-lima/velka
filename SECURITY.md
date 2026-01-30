# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Velka, please report it responsibly.

### How to Report

1. **Do NOT** open a public issue
2. Report via GitHub Security Advisories: https://github.com/wesllen-lima/velka/security/advisories/new
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### Security Principles

Velka follows these security principles:

1. **Zero Telemetry**: No data leaves your machine
2. **No Secret Storage**: Cache stores only hashes, never actual secrets
3. **Redaction by Default**: Secrets are masked in output
4. **Path Validation**: System paths cannot be scanned
5. **Secure Errors**: Error messages don't leak sensitive information

### Security Features

- Secret redaction in all output formats
- Path traversal prevention
- Secure error handling with `VELKA_DEBUG` opt-in
- Pre-commit hook safety checks
- No network calls during scanning (unless `--verify` is used to validate tokens)

## Acknowledgments

We appreciate security researchers who help keep Velka safe.
