# VELKA

**The Code Sin Judge**

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Release](https://img.shields.io/badge/Release-v1.2.0-green)](https://github.com/wesllen-lima/velka/releases)
[![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue)](LICENSE)

> *"Thou who art Undead, art chosen... to expose the guilty."*

---

## Features

- **52 Detection Rules**: AWS, GCP, Azure, GitHub, Stripe, SendGrid, Twilio, Datadog, Cloudflare, Supabase, Vercel, and more
- **Privacy First**: Zero telemetry, no network calls, secrets redacted by default
- **High Performance**: Memory-mapped I/O, parallel scanning, compiled regex
- **CI/CD Ready**: JUnit, SARIF, CSV, Markdown, HTML output formats
- **Incremental Scanning**: `--diff` and `--staged` for fast pre-commit checks
- **Git Forensics**: `--deep-scan` finds secrets buried in commit history
- **Library API**: Use as a Rust crate in your own tools

---

## Installation

### Cargo (from crates.io)

```bash
cargo install velka
```

### Cargo (from GitHub)

```bash
cargo install --git "https://github.com/wesllen-lima/velka" --locked
```

### From Source (local checkout)

```bash
cargo install --path .
```

### Docker

```bash
docker run --rm -v $(pwd):/code velka scan /code
```

### As Library

```toml
# Cargo.toml
[dependencies]
velka = "1.2"
```

```rust
use velka::{scan, Severity};

fn main() -> velka::VelkaResult<()> {
    let sins = velka::scan(std::path::Path::new("."))?;
    
    let mortal_count = sins.iter()
        .filter(|s| s.severity == Severity::Mortal)
        .count();
    
    if mortal_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}
```

---

## Usage

```bash
# Basic scan
velka scan .

# Show progress bar
velka scan . --progress

# Only changed files (fast pre-commit)
velka scan . --diff

# Only staged files
velka scan . --staged

# Git history forensics
velka scan . --deep-scan

# Only critical issues
velka scan . --mortal-only

# Different output formats
velka scan . --format json
velka scan . --format csv
velka scan . --format junit    # CI dashboards
velka scan . --format sarif    # GitHub Code Scanning
velka scan . --format markdown
velka scan . --format html

# Use configuration profile
velka scan . --profile ci

# Show full secrets (debugging only)
velka scan . --no-redact

# Verify secrets via API (opt-in; makes network calls for GitHub token, etc.)
velka scan . --verify

# Scan from stdin (e.g. pipe from git diff)
git diff | velka stdin
cat logs/*.log | velka stdin --format json

# Install pre-commit hook
velka install-hook
```

### Exit codes

- **0**: no Mortal sins found
- **1**: at least one Mortal sin found

---

## Configuration

Create `velka.toml` in your project root:

```toml
[scan]
ignore_paths = ["vendor/**", "tests/fixtures/**"]
entropy_threshold = 4.6
whitelist = ["localhost", "example.com", "test@example.com"]

[output]
redact_secrets = true

[cache]
enabled = true
location = "both"  # "project", "user", or "both"

[rules]
disable = ["HARDCODED_IP"]

[[rules.custom]]
id = "INTERNAL_API"
pattern = "MYCOMPANY_[A-Z0-9]{32}"
severity = "Mortal"
description = "Internal API key detected"

[profile.ci]
cache.enabled = false
output.redact_secrets = true

[profile.dev]
scan.entropy_threshold = 5.0
output.redact_secrets = false
```

**Inline ignores**: Add `velka:ignore` comment on any line to skip it.

---

## Detection Rules

### Mortal Sins (Critical)

| Rule | Description |
|------|-------------|
| `AWS_ACCESS_KEY` | AWS Access Key ID |
| `AWS_SECRET_KEY` | AWS Secret Access Key |
| `GOOGLE_API_KEY` | Google API Key |
| `GITHUB_TOKEN` | GitHub Personal Access Token |
| `STRIPE_SECRET` | Stripe Secret Key |
| `PRIVATE_KEY` | SSH/PGP Private Keys |
| `SLACK_WEBHOOK` | Slack Webhook URL |
| `SENDGRID_API` | SendGrid API Key |
| `TWILIO_API` | Twilio API Key |
| `NPM_TOKEN` | NPM Auth Token |
| `PYPI_TOKEN` | PyPI API Token |
| `DISCORD_TOKEN` | Discord Bot Token |
| `TELEGRAM_BOT` | Telegram Bot Token |
| `DB_CONNECTION_STRING` | Database Connection String |
| `HARDCODED_PASSWORD` | Hardcoded Password |
| `AZURE_STORAGE_KEY` | Azure Storage Account Key |
| `GCP_SERVICE_ACCOUNT` | GCP Service Account Key |
| `HEROKU_API_KEY` | Heroku API Key |
| `MAILGUN_API_KEY` | Mailgun API Key |
| `SQUARE_ACCESS_TOKEN` | Square Access Token |
| `SQUARE_OAUTH_SECRET` | Square OAuth Secret |
| `CREDIT_CARD` | Credit Card (Luhn validated) |
| `HIGH_ENTROPY` | High Entropy Strings |
| `K8S_PRIVILEGED` | Kubernetes Privileged Pod |

### Venial Sins (Warnings)

| Rule | Description |
|------|-------------|
| `JWT_TOKEN` | JWT Token |
| `HARDCODED_IP` | Hardcoded IP Address |
| `EVAL_CALL` | eval() Call |
| `DOCKER_ROOT` | Dockerfile Root User |
| `DOCKER_LATEST` | Dockerfile :latest Tag |
| `K8S_HOST_NETWORK` | Kubernetes Host Network |
| `K8S_HOST_PID` | Kubernetes Host PID |
| `GENERIC_API_KEY` | Generic API Key Pattern |
| `GENERIC_SECRET` | Generic Secret Pattern |

---

## CI/CD Integration

### GitHub Actions

Use the Velka action (installs from [crates.io](https://crates.io/crates/velka) then scans; requires Velka to be published):

```yaml
- uses: actions/checkout@v4
- uses: wesllen-lima/velka@main
  with:
    path: .
    fail-on-secrets: true
    format: terminal  # or sarif, json, junit, etc.
```

Or run Velka manually and upload SARIF:

```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- run: cargo install velka --locked
- run: velka scan . --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
velka-scan:
  script:
    - velka scan . --format junit > velka-report.xml
  artifacts:
    reports:
      junit: velka-report.xml
```

### Pre-commit Hook

**Option 1 – pre-commit framework** (add to `.pre-commit-config.yaml`):

```yaml
repos:
  - repo: https://github.com/wesllen-lima/velka
    rev: v1.2.0
    hooks:
      - id: velka
```

Requires `velka` on PATH (`cargo install velka`). Then run `pre-commit run velka`.

**Option 2 – Git hook only**:

```bash
velka install-hook
```

---

## Security

- **Zero Telemetry**: No data ever leaves your machine
- **Redaction by Default**: Secrets are masked in output (`AKIA****MPLE`)
- **Secure Cache**: Only stores file hashes, never secret content
- **Path Validation**: System paths (`/proc`, `/sys`, `/dev`) cannot be scanned
- **Secure Errors**: Error messages don't leak sensitive paths

---

## Performance

- **Parallel Scanning**: Uses `ignore` crate's parallel walker
- **Memory-Mapped I/O**: Files >1MB use `mmap` for efficiency
- **Compiled Regex**: All patterns compiled once via `std::sync::LazyLock`
- **Lock-free Channels**: `crossbeam-channel` for zero-contention
- **Smart Skipping**: Binary detection via magic bytes, minified code skipped

### Benchmarks

Run `cargo bench` to reproduce. Typical results (release build, cache disabled):

| Files | Velka (median) |
|-------|----------------|
| 100   | ~2 ms          |
| 1,000 | ~4.5 ms        |
| 5,000 | ~12 ms         |
| 10,000| ~21 ms         |

Velka is designed to be significantly faster than alternatives (e.g. TruffleHog, detect-secrets) due to Rust's zero-cost abstractions, parallel file walking, and memory-mapped I/O. Run both on your codebase to compare.

---

## VS Code Extension (MVP)

A minimal VS Code extension is in `vscode-extension/`. It adds a command **Velka: Scan for secrets** that runs Velka on the workspace and shows output in a channel. Requires `velka` on PATH (`cargo install velka`). See `vscode-extension/README.md` for setup.

---

## Documentation

- **[Contributing](CONTRIBUTING.md)** - How to contribute
- **[Changelog](CHANGELOG.md)** - Version history
- **[Security Policy](SECURITY.md)** - Vulnerability reporting

## License

Licensed under **MIT OR Apache-2.0**.

See [`LICENSE`](LICENSE), [`LICENSE-MIT`](LICENSE-MIT), and [`LICENSE-APACHE`](LICENSE-APACHE).
