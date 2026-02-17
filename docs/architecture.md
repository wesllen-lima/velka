# Velka Architecture: Engine & Scoring

This document explains how Velka's detection engine works internally, covering the Ensemble Scoring system, rule pipeline, and plugin architecture.

---

## High-Level Flow

```
Input (files/stdin/git history)
  |
  v
[File Walker] ── parallel via `ignore` crate + rayon thread pool
  |
  v
[File Reader] ── memmap2 for large files, UTF-8 fallback for small
  |
  v
[Per-Line Analysis Pipeline]
  |
  ├─ 1. Rule Matching (regex)
  ├─ 2. Entropy Calculation (Shannon)
  ├─ 3. Context Scoring (structural analysis)
  ├─ 4. Known Example Filter
  ├─ 5. Honeytoken Detection
  ├─ 6. ML Classifier (optional ensemble)
  └─ 7. Confidence Aggregation
  |
  v
[Sin Emission] ── crossbeam-channel (lock-free) ──> Collector
  |
  v
[Output Formatter] ── terminal, JSON, SARIF, JUnit, CSV, HTML, Markdown
```

---

## Ensemble Scoring

Velka uses a multi-factor scoring system to minimize false positives. Each detected match goes through several confidence adjustments before being reported.

### 1. Pattern Matching (Base)

All 52+ built-in rules use compiled `Regex` patterns (via `std::sync::LazyLock`). Each rule has a severity (`Mortal` or `Venial`) and a unique ID. Pattern compilation happens once at process startup.

```rust
// src/engine/rules.rs
pub static RULES: &[Rule] = &[
    Rule {
        id: "AWS_ACCESS_KEY",
        pattern: define_regex!(r"AKIA[0-9A-Z]{16}"),
        severity: Severity::Mortal,
        ..
    },
    // ...
];
```

### 2. Shannon Entropy

After a regex match, Velka computes the Shannon entropy of the matched string. This filters out low-entropy strings that look like patterns but aren't actual secrets (e.g., `AKIA_EXAMPLE_KEY_HERE`).

The entropy threshold is configurable (`scan.entropy_threshold` in `velka.toml`, default `4.6`) and is **adaptive per file type**:

- `.env` files: threshold lowered by 0.5 (secrets tend to have lower entropy in assignment context)
- `.yaml`/`.json`: threshold lowered by 0.3
- Source code: base threshold

### 3. Context Scoring

Velka inspects the surrounding code (typically 3 lines above/below) to determine if the match is in a real assignment, a comment, a test fixture, or a string literal:

| Factor | Confidence Effect |
|--------|------------------|
| Assignment (`=`, `:`, `=>`) | +0.15 |
| Variable name contains `key`, `secret`, `token`, `password` | +0.20 |
| Inside a comment (`//`, `#`, `/* */`) | -0.30 |
| Inside test file (`test_`, `_test.`, `spec.`) | -0.20 |
| Known placeholder (`TODO`, `FIXME`, `xxx`, `changeme`) | -0.50 |
| Base64/hex-like structure | +0.10 |

### 4. Known Example Filter

A hardcoded list of known example/documentation values (like `AKIAIOSFODNN7EXAMPLE`) is maintained in `src/engine/known_examples.rs`. Any match against these is automatically suppressed.

### 5. Honeytoken Detection

If Velka's own honeytokens are detected (generated via `velka honeytoken generate`), they are flagged as such with a special annotation rather than being reported as leaks.

### 6. ML Classifier (Optional)

The ML classifier (`src/engine/ml_classifier.rs`) uses a lightweight feature-based model (no external runtime). Features include:

- Character class distribution (uppercase, lowercase, digits, symbols)
- Bigram frequency analysis
- String length normalization
- Prefix/suffix pattern matching

The classifier outputs a probability score [0.0, 1.0] which is blended with the rule-based confidence.

### 7. Final Confidence

```
final_confidence = base_confidence
    + entropy_factor
    + context_score
    + ml_adjustment
    - known_example_penalty
```

A finding is reported only if `final_confidence >= 0.5`. This threshold is intentionally conservative to achieve <0.1% false positive rate.

---

## Dynamic Rules Plugin System

Users can extend Velka with custom rules via the `DynamicRulesManager`:

### Rule Sources

1. **Inline** (`velka.toml`): Under `[[rules.custom]]` sections
2. **External files** (`~/.velka/rules.d/`): `.toml` or `.yaml` files
3. **Remote** (`velka rules install <url>`): Downloaded and cached locally

### Rule Format (TOML)

```toml
[[rules]]
id = "INTERNAL_API"
pattern = "MYCOMPANY_[A-Z0-9]{32}"
severity = "Mortal"
description = "Internal API key detected"
```

### Rule Format (YAML)

```yaml
rules:
  - id: INTERNAL_API
    pattern: "MYCOMPANY_[A-Z0-9]{32}"
    severity: Mortal
    description: Internal API key detected
```

### Hot-Reloading

The `DynamicRulesManager` uses `notify` (inotify/kqueue) to watch `~/.velka/rules.d/` for changes. When a file is added, modified, or removed, rules are recompiled in-memory without restarting the process. This is particularly useful for the LSP server which runs as a long-lived process.

---

## Cache Architecture

Velka uses a two-tier caching system (`src/engine/cache.rs`):

| Tier | Location | Scope |
|------|----------|-------|
| Project | `.velka-cache/` in project root | Per-project |
| User | `~/.velka/cache/` | Cross-project |

Cache entries are keyed by `(file_path, sha256_hash, rule_version)`. This means:
- Unchanged files are never re-scanned
- Rule updates automatically invalidate stale entries
- Cache is serialized via `bincode` for minimal disk/memory overhead

The cache uses `RwLock` for concurrent reads during parallel scanning, with batch writes flushed once per run.

---

## Cloud-Native Architecture

### K8s Admission Controller (`src/engine/k8s.rs`)

Runs as a ValidatingWebhookConfiguration. The webhook server:

1. Receives `AdmissionReview` requests from the Kubernetes API server
2. Serializes the Pod/Deployment manifest to YAML
3. Runs Velka's `scan_content()` on the manifest
4. Returns `allowed: false` with details if mortal secrets are found

Supports TLS via `rustls` for production deployments.

### Runtime Log Scanner (`src/engine/runtime_scanner.rs`)

Monitors container logs in real-time:

- **Stream mode**: Scans an async reader (stdin, file, network stream) line-by-line
- **Tail mode** (`--follow`): Seeks to end of file and watches for new lines
- Uses the same rule engine as the file scanner for consistency

### Distributed Scanning (`src/engine/dist.rs`)

Orchestrates scans across multiple repositories:

- **Orchestrator**: Distributes `ScanJob` objects round-robin across worker URLs
- **Worker**: HTTP server (axum) that clones repos to temp dirs and runs local scans
- Communication via JSON over HTTP, results aggregated asynchronously

---

## Module Map

```
src/
├── domain/          # Core types: Sin, Rule, Severity
├── config.rs        # VelkaConfig, profiles, velka.toml parsing
├── engine/
│   ├── scanner.rs       # Main file walker + per-file scan
│   ├── analyzer.rs      # Per-line analysis (entropy, context, confidence)
│   ├── rules.rs         # 52+ compiled rules + DynamicRulesManager
│   ├── cache.rs         # Two-tier scan cache (bincode)
│   ├── necromancer.rs   # Git history scanning (git2)
│   ├── honeytoken.rs    # Honeytoken generation + detection
│   ├── ml_classifier.rs # Feature-based ML classifier
│   ├── verifier.rs      # Online verification (GitHub token, etc.)
│   ├── migrate.rs       # Secret-to-env migration
│   ├── quarantine.rs    # File quarantine for pre-commit
│   ├── lsp.rs           # Language Server Protocol (tower-lsp)
│   ├── k8s.rs           # Kubernetes admission webhook
│   ├── runtime_scanner.rs # Runtime log monitoring
│   ├── dist.rs          # Distributed scan orchestration
│   └── ...
├── output/
│   └── formatter.rs     # All output formats (terminal, JSON, SARIF, etc.)
├── ui/                  # TUI (ratatui) dashboard
└── main.rs              # CLI entry point (clap)
```
