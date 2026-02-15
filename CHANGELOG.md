# Changelog

All notable changes to Velka will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **K8s Admission Controller**: `velka k8s webhook` starts a ValidatingWebhook server (axum + TLS) that blocks Pods with secrets in manifests
- **K8s Manifest Scan**: `velka k8s scan <file>` scans local YAML manifests for secrets
- **Runtime Log Scanner**: `velka runtime [sources...] [--follow]` monitors container logs (stdin or file) for leaked secrets in real-time
- **Distributed Scanning**: `src/engine/dist.rs` with `ScanOrchestrator` (round-robin job distribution) and HTTP worker nodes
- **GitHub Action (Official)**: `.github/actions/velka-scan/action.yml` composite action with auto-install, SARIF support, diff-only mode
- **Shell Completions**: `velka completions <shell>` generates autocompletion scripts for Bash, Zsh, Fish, Elvish, PowerShell
- **Architecture Docs**: `docs/architecture.md` with full Ensemble Scoring explanation, rule plugin system, and module map

### Changed
- **Dependencies**: Added `axum`, `hyper-util`, `tokio-rustls`, `rustls`, `rustls-pemfile`, `tokio-util`, `tokio-stream`, `bytes`, `clap_complete`
- **Tokio features**: Added `fs`, `process`, `time` features
- **`.gitignore`**: Extended with K8s TLS certs, LSP debug logs, bincode caches, quarantine dirs

### Improved (Diamond Polish)
- **Code Quality**: Zero clippy warnings with `-D warnings`; all pedantic lints resolved
- **Unwrap Audit**: Eliminated all `unwrap()` in production code; static regexes use `LazyLock`
- **Project Structure**: Extracted `src/cli/` module (scan, rotate, hooks, init) from `main.rs` (1271 -> 387 lines); added `src/presets.rs`
- **Landing Page**: Rewrote `docs/index.html` — dark theme, CSS Grid, no external JS dependencies, responsive mobile-first design
- **CI/CD Pipeline**: Added parallel gate jobs (audit, lint, test) before build-release; `swatinem/rust-cache@v2` on all jobs; `cargo audit` + `cargo clippy -- -D warnings` + `cargo fmt --check` as gates

## [1.2.0] - 2026-01-29

### Added
- **Report format**: `--format report` for Before/After remediation (redacted snippets and suggested env-based replacement)
- **Migrate to env**: `--migrate-to-env` to move secrets into `.env` and update source to use env vars; `--dry-run`, `--yes`, `--env-file`; migration report is metadata-only (no secret values). Use responsibly: ensure `.env` is in `.gitignore` and never commit it.
- **Verification**: `--verify` flag to validate GitHub tokens via API (opt-in, network call)
- **Stdin**: `velka stdin` to scan content from pipe (e.g. `git diff | velka stdin`)
- **Benchmarks**: Cache cold vs cache hit benchmarks (`scan_1000_files_cache_cold`, `scan_1000_files_cache_hit`) in `benches/scan_bench.rs`; run with `cargo bench scan_1000_files_cache`
- **VS Code**: MVP extension in `vscode-extension/` (command: Velka: Scan for secrets)
- **GitHub Action**: `action.yml` for use as `uses: wesllen-lima/velka@main`
- **Pre-commit**: `.pre-commit-hooks.yaml` for pre-commit framework
- **Detectors**: 20+ new rules (Datadog, New Relic, Cloudflare, OpenAI, Supabase, Vercel, MongoDB Atlas, Sentry, Algolia, Notion, Linear, Figma, Airtable, DigitalOcean, PlanetScale, Railway, Render, Netlify, etc.)

### Changed
- **Performance**: `ScanCache` uses `RwLock` instead of `Mutex` for parallel reads
- **Dependencies**: Replaced `once_cell::Lazy` with `std::sync::LazyLock` (Rust 1.80+)
- **CLI**: `scan_with_options` / `run_*` take references where appropriate (Clippy)

### Fixed
- Clippy compliance (`-D warnings`) across the codebase

## [1.1.0] - 2026-01-28

### Added
- **Security Hardening**
  - Secret redaction in all output formats (enabled by default)
  - Path validation to prevent scanning system directories
  - Secure error handling (no path leakage)
  - `--no-redact` flag for debugging

- **New Output Formats**
  - CSV export
  - JUnit XML for CI integration
  - SARIF for GitHub Code Scanning
  - Markdown reports
  - HTML reports with modern dark theme

- **Incremental Scanning**
  - `--diff` flag to scan only changed files
  - `--staged` flag for pre-commit scanning
  - Progress bar with `--progress` flag

- **Configuration 2.0**
  - Profile support (`--profile ci`, `--profile dev`)
  - Custom rules via TOML configuration
  - Whitelist for false positive management
  - Cache configuration

- **Performance**
  - Memory-mapped I/O for large files (>1MB)
  - Binary detection with `infer` crate
  - Skip minified files (>10k chars per line)
  - Arc-based shared data for parallel workers

- **New Detection Rules**
  - SendGrid API keys
  - Twilio API keys
  - NPM tokens
  - PyPI tokens
  - Discord bot tokens
  - Telegram bot tokens
  - Database connection strings
  - Hardcoded passwords
  - Azure Storage keys
  - GCP Service Account keys
  - Heroku API keys
  - Mailgun API keys
  - Square tokens
  - Generic API key patterns
  - Kubernetes hostNetwork/hostPID

- **Library API**
  - `velka::scan()` for simple scanning
  - `velka::scan_with_config()` for custom configuration
  - `velka::scan_with_options()` for advanced usage

- **DevOps**
  - Multi-stage Dockerfile with distroless image
  - GitHub Actions workflow
  - GitLab CI template
  - Pre-commit hook improvements

### Changed
- Improved AWS key detection patterns
- Enhanced SSH private key detection (PGP, ENCRYPTED)
- Better error messages with `VELKA_DEBUG` mode
- Exit code 1 when mortal sins are found
- Sorted output by file path and line number

### Fixed
- Hardcoded entropy threshold in git history scan
- Silent error handling in walker callbacks
- Pre-commit hook checks for existing hooks

## [0.1.0] - Initial Release

### Added
- Basic secret scanning
- Git history scanning
- Complexity analysis
- Terminal and JSON output
- Pre-commit hook installation
