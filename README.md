# VELKA ⚖️

**The Code Sin Judge**

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Release](https://img.shields.io/badge/Release-v1.0.0-green)](https://github.com/your-org/velka/releases)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

> *"Thou who art Undead, art chosen... to expose the guilty."*

---

## ⚡ Performance

**Processed 1,216 lines of code in 0.06s.**

Multithreaded architecture using Rayon. Zero-allocation entropy calculation. Compiled regex patterns. Lock-free message passing.

---

## Why Velka?

Traditional secret scanners rely on regex patterns. They catch known secrets (AWS keys, GitHub tokens) but miss everything else.

**Velka goes deeper:**

- **Math > Regex**: Validates Credit Cards via Luhn Algorithm & detects High Entropy secrets using Shannon entropy
- **Forensics**: Git History Scanning (`--deep-scan`) finds secrets buried in commit history
- **DevSecOps**: Audits Dockerfiles (`USER root`, `FROM :latest`) and Kubernetes manifests (`privileged: true`)

**Local-first. No cloud. No API keys. No network calls.**

---

## Installation & Usage

### Install

```bash
cargo install --path .
```

### Scan

```bash
# Scan current directory
velka scan .

# Scan with git history forensics
velka scan . --deep-scan

# JSON output for CI/CD
velka scan . --format json

# Only critical secrets
velka scan . --mortal-only
```

### Automation

```bash
# Install pre-commit hook (blocks commits with mortal sins)
velka install-hook
```

---

## Configuration

Create `velka.toml` in your project root (copy from `velka.example.toml`):

```toml
[scan]
# Additional ignore patterns (glob syntax)
ignore_paths = [
    "**/*.sample",
    "tests/fixtures/**",
    "vendor/**",
]

# Entropy threshold (default: 4.6)
entropy_threshold = 4.6

[rules]
# Disable specific rules globally
disable = ["HARDCODED_IP"]
```

**Default ignore patterns** (always active):
- `**/target/**`, `**/.git/**`, `**/node_modules/**`
- `**/*.lock`, `**/*.png`, `**/*.jpg`

**Inline ignores**: Add `velka:ignore` comment on any line to skip scanning.

---

## Detection Rules

| Rule | Pattern | Severity |
|------|---------|----------|
| `AWS_ACCESS_KEY` | `AKIA[0-9A-Z]{16}` | Mortal |
| `AWS_SECRET_KEY` | `aws_secret_access_key` + 40-char string | Mortal |
| `GOOGLE_API_KEY` | `AIza[0-9A-Za-z\-_]{35}` | Mortal |
| `GITHUB_TOKEN` | `gh[pousr]_[A-Za-z0-9_]{36,}` | Mortal |
| `STRIPE_SECRET` | `sk_live_[0-9a-zA-Z]{24,}` | Mortal |
| `PRIVATE_KEY` | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH) PRIVATE KEY-----` | Mortal |
| `SLACK_WEBHOOK` | `hooks.slack.com/services/...` | Mortal |
| `CREDIT_CARD` | `\b(?:\d[ -]*?){13,16}\b` | Mortal | Luhn validated |
| `HIGH_ENTROPY` | Shannon entropy > threshold | Mortal | Configurable |
| `DOCKER_ROOT` | `USER root` | Venial | Infrastructure |
| `DOCKER_LATEST` | `FROM ...:latest` | Venial | Infrastructure |
| `K8S_PRIVILEGED` | `privileged: true` | Mortal | Infrastructure |
| `JWT_TOKEN` | `eyJ...` base64 structure | Venial |
| `HARDCODED_IP` | IPv4 addresses | Venial |
| `EVAL_CALL` | `eval(` | Venial |
| `COMPLEXITY_SIN` | Function complexity > 15 | Venial | Requires `--complexity` |

---

## Sample Output

```
┌─────────────────────────────────────────────────────────
│ THE BOOK OF THE GUILTY IS OPEN...
└─────────────────────────────────────────────────────────

▸ src/config.rs
  [LINE 42] MORTAL - AWS Access Key ID detected
    41 │ // TODO: move to env
    42 │ let key = "AKIAIOSFODNN7EXAMPLE";
    43 │ let region = "us-east-1";

  [LINE 87] MORTAL - High entropy string detected (potential secret)
    86 │ const SIGNING_KEY: &str =
    87 │     "kJf8$mNq2#pLw9@xRt4&yUv6!zA3^cBe5";
    88 │

═══════════════════════════════════════════════════════════
VERDICT: 2 Mortal Sins condemned.
```

---

## Architecture

- **Parallel File Walking**: `ignore::WalkBuilder` + `rayon` for CPU-bound parallelism
- **Stack-allocated Entropy**: `[usize; 256]` frequency table, zero heap allocations
- **Compiled Regex**: All patterns compile once via `once_cell::sync::Lazy`
- **Lock-free Channels**: `crossbeam-channel` for zero-contention message passing

---

## Known Limitations

- **Minified code**: High entropy by nature. Add `*.min.js` to ignore patterns.
- **Binary detection**: Heuristic-based. Some edge cases may slip through.
- **No incremental scanning**: Full tree scan on every run.

---

## Why Rust?

Memory safety without garbage collection. Fearless concurrency. A type system that catches bugs at compile time. Rayon makes parallelism trivial.

We could have written this in Python. It would be 10x slower and require a runtime.

---

## License

MIT
