# Changelog

All notable changes to Velka will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - 2026-02-17

### Added
- **AST-Powered Scope Analysis** (`src/engine/ast_analyzer.rs`): detects test functions, `#[cfg(test)]` blocks, docstrings, and test files across 10 languages; automatically down-scores findings in non-production scope
- **Permission-Aware Verification** (`--verify`): extracts live IAM permissions (AWS), token scopes (GitHub), and payment capabilities (Stripe) and classifies blast radius as Critical / High / Medium / Low / Info
- **Risk Level Classification** (`RiskLevel` enum in `src/domain/sin.rs`): every finding now carries a structured risk level surfaced in all output formats
- **Verification Detail** (`VerificationDetail` struct): structured result from `--verify` with status, permissions list, owner, and expiry
- **IaC Security Scanner** (`src/engine/iac_analyzer.rs`): dedicated rules for Terraform (hardcoded credentials, public S3, open security groups, unencrypted RDS/EBS), Kubernetes (privileged pods, hostNetwork/PID, missing limits, secrets in env), and Dockerfile (root user, latest tag, secrets in ENV/ARG, curl-pipe-bash)
- **Baseline & Drift Detection** (`src/engine/baseline.rs` + `src/cli/baseline.rs`): `velka baseline save`, `velka baseline diff`, `velka baseline show` — tracks secret posture over time, keyed per repo root
- **15+ new IaC detection rules**: `TF_HARDCODED_CREDS`, `TF_PUBLIC_S3`, `TF_OPEN_SECURITY_GROUP`, `TF_UNENCRYPTED_RDS`, `TF_UNENCRYPTED_EBS`, `K8S_PRIVILEGED`, `K8S_HOST_NETWORK`, `K8S_HOST_PID`, `K8S_NO_RESOURCE_LIMITS`, `K8S_SECRET_ENV_VAR`, `K8S_LATEST_IMAGE`, `DOCKER_ROOT_USER`, `DOCKER_LATEST_TAG`, `DOCKER_SECRET_ENV`, `DOCKER_PRIVILEGED`, `DOCKER_CURL_BASH`

### Improved
- **40% fewer false positives** on real-world codebases due to AST scope filtering — without relaxing entropy thresholds
- **Richer `--verify` output**: now shows permission set, account/user context, and expiry alongside active/invalid status (previously only active/invalid)
- **Baseline-aware CI**: `velka baseline diff` exits 0 when no new findings, enabling zero-noise pipelines

### Technical
- New modules: `engine::ast_analyzer`, `engine::iac_analyzer`, `engine::baseline`, `cli::baseline`
- `Sin` struct gains `verification_detail: Option<VerificationDetail>` field; `RiskLevel` is embedded inside `VerificationDetail`
- 329 tests passing (up from ~280 in v1.3.0); added regression, property-based (`proptest`), and IaC unit tests
- ~1,700 new lines of production code across sprints 11–14

## [1.3.0] - 2026-02-10

### Added
- **`scan_str()` public API**: Scan a string directly for secrets (useful for testing and piped input)
- **`--god-mode` flag**: Full deep analysis — semantic decoding, bloom dedup, ML scoring — all in one flag
- **PII Compliance Validators**: NIF (Portugal), DNI (Spain), SSN (US), IBAN (generic MOD-97), CNPJ Alphanumeric (2026 format)
- **ML Classifier Integration**: Ensemble scoring now runs on every finding, confidence visible in JSON and terminal output
- **Extensible Structural Validators**: Rule metadata (`expected_len`, `required_prefix`, `charset`) drives validation — no more hardcoded match arms
- **Adaptive Entropy Thresholds**: Per-extension tuning (`.lock`, `.svg`, `.min.js`, `.md`, test files) to reduce false positives
- **Large File Skip**: Files >10 MB skipped automatically (configurable via `velka.toml`)
- **Parallel Line Scanning**: Files >1000 lines use rayon `par_chunks` for faster processing
- **Rustdoc**: Module-level `//!` docs and field-level `///` docs on all public types
- **LSP Server**: Real-time secret detection via Language Server Protocol (`velka lsp`)
- **Interactive TUI**: Terminal dashboard for triaging findings with syntax highlighting and entropy visualization (`velka tui`)
- **K8s Admission Controller**: Block Pods/Deployments with secrets before cluster admission (`velka k8s webhook`)
- **Runtime Log Scanner**: Monitor container stdout for accidentally leaked secrets (`velka runtime`)

### Changed
- **Semantic Analysis**: Now opt-in — only runs with `--god-mode` or `--semantic` (was always-on)
- **Scan Mode Flags**: `--diff`, `--staged`, `--since` are mutually exclusive via Clap `ArgGroup`
- **README**: Rewritten header with concise quick-start (what, install, use, why)

### Removed
- **`dist.rs`**: Distributed orchestrator removed (unused, no CLI integration, premature complexity)
- **`InstallHook` command**: Duplicate of `velka hook install`
- **`fs2` dependency**: Not used anywhere in the codebase

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
