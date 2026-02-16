# Velka Privacy Policy

## Core Principles

Velka is built on three non-negotiable privacy pillars:

### 1. Local-First

All scanning, analysis, and reporting happens **entirely on your machine**. Source code, scan results, and cached hashes never leave the local filesystem. There is no cloud component, no backend server, and no SaaS dependency.

### 2. No-Telemetry

Velka contains **zero telemetry, analytics, or tracking code**. No usage metrics are collected. No crash reports are sent. No anonymous statistics are gathered. This is enforced at the dependency level — no analytics crates are included in the build.

### 3. Air-Gapped by Default

Velka makes **no network connections** during normal operation. The binary can run in fully air-gapped environments without any degradation in functionality.

The only exception is the **opt-in** `--verify` flag, which performs active verification of detected secrets against their respective APIs (e.g., AWS STS, GitHub API). This feature:

- Is **disabled by default** — you must explicitly pass `--verify`
- Is clearly documented as making network calls
- Can be audited in `src/engine/verifier.rs`
- Never transmits your source code — only the detected token is sent to its own provider's API for validation

## Data Storage

| Data | Location | Contains Secrets? |
|------|----------|-------------------|
| Scan cache | `~/.cache/velka/` or `.velka-cache/` | No — only file content hashes (SHA-256) |
| Dynamic rules | `~/.velka/rules.d/` | No — only detection patterns |
| Quarantine records | `.velka-quarantine/` | No — only metadata and file paths |

## Redaction

All output formats redact secret values by default (e.g., `AKIA****MPLE`). The `--no-redact` flag is available for debugging but is never enabled automatically.

## Verification

To independently verify these claims:

```bash
# Confirm no network dependencies in default build
cargo tree | grep -iE "hyper|reqwest|curl"
# reqwest is present but only used behind the --verify flag

# Confirm no telemetry crates
cargo tree | grep -iE "sentry|segment|mixpanel|amplitude|analytics|telemetry"
# (no output)

# Run with network monitoring to confirm zero outbound connections
strace -e trace=network velka scan . 2>&1 | grep connect
# (no output without --verify)
```

## Contact

For security concerns, see [SECURITY.md](SECURITY.md).
