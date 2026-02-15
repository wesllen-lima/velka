# VELKA

**English** | [Portugues (BR)](README.pt-BR.md)

---

**The Code Sin Judge**

[![CI](https://github.com/wesllen-lima/velka/actions/workflows/ci.yml/badge.svg)](https://github.com/wesllen-lima/velka/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/velka.svg)](https://crates.io/crates/velka)
[![docs.rs](https://docs.rs/velka/badge.svg)](https://docs.rs/velka)
[![Downloads](https://img.shields.io/crates/d/velka.svg)](https://crates.io/crates/velka)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue)](LICENSE)

> *"Thou who art Undead, art chosen... to expose the guilty."*

---

## Features

- **52+ Detection Rules**: AWS, GCP, Azure, GitHub, Stripe, SendGrid, Twilio, Datadog, Cloudflare, Supabase, Vercel, and more
- **Privacy First**: Zero telemetry, no network calls, secrets redacted by default
- **High Performance**: Memory-mapped I/O, parallel scanning, compiled regex
- **CI/CD Ready**: JUnit, SARIF, CSV, Markdown, HTML output formats
- **Incremental Scanning**: `--diff` and `--staged` for fast pre-commit checks
- **Git Forensics**: `--deep-scan` finds secrets buried in commit history
- **Library API**: Use as a Rust crate in your own tools
- **LSP Server**: Real-time secret detection in your editor
- **Interactive TUI**: Terminal dashboard for triaging findings
- **ML Classifier**: Ensemble scoring for <0.1% false positives
- **K8s Admission Controller**: Block Pods with secrets in manifests
- **Runtime Log Scanner**: Monitor container stdout for secret leaks

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
velka scan . --format report   # Before/After remediation (redacted)

# Use configuration profile
velka scan . --profile ci

# Show full secrets (debugging only)
velka scan . --no-redact

# Verify secrets via API (opt-in; makes network calls for GitHub token, etc.)
velka scan . --verify

# Migrate secrets to .env and update source (opt-in; requires .env in .gitignore)
velka scan . --migrate-to-env --dry-run   # Preview only
velka scan . --migrate-to-env --yes       # Apply without confirmation
velka scan . --migrate-to-env             # Interactive confirmation
velka scan . --migrate-to-env --env-file .env.local

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

## LSP Server (Editor Integration)

Velka includes a built-in Language Server Protocol server that provides real-time secret detection as you type.

<!-- TODO: Replace with actual GIF recording -->
<!-- ![Velka LSP Demo](docs/assets/lsp-demo.gif) -->

### Setup

```bash
# Start the LSP server (stdio transport)
velka lsp
```

### VS Code

Add to your `settings.json`:

```json
{
  "velka.lsp.enabled": true,
  "velka.lsp.path": "velka"
}
```

Or use the VS Code extension in `vscode-extension/`.

### Neovim (nvim-lspconfig)

```lua
require('lspconfig').velka.setup{
  cmd = { "velka", "lsp" },
  filetypes = { "*" },
}
```

### Features

- Diagnostics on save: warnings/errors for detected secrets
- Works with any editor supporting LSP (VS Code, Neovim, Helix, Zed, Emacs)
- Uses the same rule engine and ML classifier as the CLI
- Hot-reloads dynamic rules from `~/.velka/rules.d/`

---

## Interactive TUI

A full terminal dashboard for triaging and managing secret findings.

<!-- TODO: Replace with actual GIF recording -->
<!-- ![Velka TUI Demo](docs/assets/tui-demo.gif) -->

```bash
# Launch TUI on current directory
velka tui .

# Include git history findings
velka tui . --deep-scan
```

### Controls

| Key | Action |
|-----|--------|
| `j`/`k` or arrows | Navigate findings |
| `Enter` | View finding details with syntax highlighting |
| `e` | Open entropy visualizer |
| `q` | Quit |
| `?` | Help |

### Features

- File explorer with syntax-highlighted code preview
- Entropy density visualization (bar charts)
- ML confidence scores per finding
- Keyboard-driven workflow for security triage

---

## ML Classifier

Velka uses an ensemble scoring system to achieve <0.1% false positive rate. No external ML runtime required.

### How it works

1. **Pattern match** (regex) establishes base confidence
2. **Shannon entropy** filters low-entropy false positives
3. **Context scoring** analyzes surrounding code (assignments, comments, tests)
4. **ML features**: character class distribution, bigram frequency, structural analysis
5. **Final confidence** = weighted blend of all factors

```bash
# Verify output includes confidence scores
velka scan . --format json | jq '.[].confidence'
```

See [docs/architecture.md](docs/architecture.md) for the full technical explanation.

---

## Kubernetes Integration

### Admission Controller (Webhook)

Block Pods and Deployments that contain secrets in their manifests before they reach the cluster.

```bash
# Start admission webhook (plain HTTP for development)
velka k8s webhook --addr 0.0.0.0:8443

# With TLS (production)
velka k8s webhook --addr 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem
```

Register with Kubernetes:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: velka-secret-scanner
webhooks:
  - name: velka.security.io
    clientConfig:
      service:
        name: velka-webhook
        namespace: velka-system
        path: /validate
    rules:
      - apiGroups: [""]
        resources: ["pods", "secrets", "configmaps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
    failurePolicy: Ignore
    sideEffects: None
    admissionReviewVersions: ["v1"]
```

### Manifest Scanning

Scan local YAML files without running the webhook server:

```bash
velka k8s scan deployment.yaml
```

---

## Runtime Log Scanner

Monitor container logs in real-time for accidentally leaked secrets.

```bash
# Scan from stdin (pipe from docker/kubectl)
kubectl logs -f my-pod | velka runtime

# Scan log files
velka runtime /var/log/app.log /var/log/worker.log

# Follow mode (tail -f behavior)
velka runtime /var/log/app.log --follow
```

Exits with code 1 if mortal secrets are detected. Useful as a sidecar container or log monitoring daemon.

---

## Shell Completions

Generate autocompletion scripts for your shell:

```bash
# Bash
velka completions bash > ~/.local/share/bash-completion/completions/velka

# Zsh
velka completions zsh > ~/.zfunc/_velka

# Fish
velka completions fish > ~/.config/fish/completions/velka.fish

# PowerShell
velka completions powershell > velka.ps1
```

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

### Quick Init

```bash
velka init --preset balanced  # also: strict, ci, monorepo
```

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

### GitHub Actions (Official Action)

```yaml
- uses: actions/checkout@v4
- uses: wesllen-lima/velka/.github/actions/velka-scan@main
  with:
    path: .
    format: terminal
    mortal-only: 'true'
    fail-on-secrets: 'true'
    # diff-only: 'true'    # PR mode: only scan changed files
    # deep-scan: 'true'    # Also scan git history
    # since: 'main'        # Incremental: changes since branch
```

### GitHub Actions (Manual + SARIF)

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

**Option 1 - pre-commit framework** (add to `.pre-commit-config.yaml`):

```yaml
repos:
  - repo: https://github.com/wesllen-lima/velka
    rev: v1.2.0
    hooks:
      - id: velka
```

Requires `velka` on PATH (`cargo install velka`). Then run `pre-commit run velka`.

**Option 2 - Git hook only**:

```bash
velka hook install           # Standard (blocks mortal only)
velka hook install --strict  # Strict (blocks all sins)
```

---

## Honeytokens

Generate and inject canary tokens to detect unauthorized access:

```bash
# Generate and inject to .env.example
velka honeytoken generate --target .env.example

# Also inject to README.md
velka honeytoken generate --target .env.example --readme
```

Velka automatically detects its own honeytokens during scans and flags them separately.

---

## Secret Rotation

Get step-by-step rotation guides for detected secrets:

```bash
# Show rotation guidance
velka rotate .

# Filter by rule
velka rotate . --rule AWS_ACCESS_KEY

# Show executable CLI commands
velka rotate . --commands

# Mark as remediated
velka rotate . --mark-remediated
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
- **Batch Cache Writes**: Cache misses are buffered and flushed once per run to reduce RwLock contention

### Benchmarks

Run `cargo bench` to reproduce. Benchmarks live in `benches/scan_bench.rs`.

**Throughput (cache disabled):**

| Files | Benchmark name       | Typical median |
|-------|----------------------|----------------|
| 100   | `scan_100_files`     | ~2 ms          |
| 1,000 | `scan_1000_files`    | ~4.5 ms        |
| 5,000 | `scan_5000_files`    | ~12 ms         |
| 10,000| `scan_10000_files`    | ~21 ms         |

**Cache impact (1,000 files, cache enabled):**

| Benchmark name              | Description                          |
|-----------------------------|--------------------------------------|
| `scan_1000_files_cache_cold`| First run: full scan, cache populated|
| `scan_1000_files_cache_hit` | Second run: cache hit, no re-scan    |

Run only cache benchmarks: `cargo bench scan_1000_files_cache`. Run a single bench: `cargo bench scan_1000_files`.

Velka is designed to be significantly faster than alternatives (e.g. TruffleHog, detect-secrets) due to Rust's zero-cost abstractions, parallel file walking, and memory-mapped I/O. Run both on your codebase to compare.

---

## Architecture

For a deep dive into the Ensemble Scoring engine, rule plugin system, and module map, see **[docs/architecture.md](docs/architecture.md)**.

---

## Documentation

- **[Architecture](docs/architecture.md)** - Engine internals and scoring system
- **[Contributing](CONTRIBUTING.md)** - How to contribute
- **[Changelog](CHANGELOG.md)** - Version history
- **[Security Policy](SECURITY.md)** - Vulnerability reporting

## License

Licensed under **MIT OR Apache-2.0**.

See [`LICENSE`](LICENSE), [`LICENSE-MIT`](LICENSE-MIT), and [`LICENSE-APACHE`](LICENSE-APACHE).
