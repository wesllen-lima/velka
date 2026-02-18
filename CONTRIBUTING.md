# Contributing to Velka

Thank you for your interest in contributing to Velka!

## Development Setup

1. Install Rust (1.70+): https://rustup.rs/
2. Clone the repository
3. Run tests: `cargo test`
4. Run lints: `cargo clippy`

## Code Standards

### Rust Style
- Run `cargo fmt` before committing
- All code must pass `cargo clippy -- -D warnings`
- No `unwrap()` or `expect()` in production code (use `?` or proper error handling)
- Use `anyhow` for binary errors, `thiserror` for library errors

### Commit Messages
- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Keep the first line under 72 characters
- Reference issues when applicable: `fix: handle empty files (#123)`

### Branching and Protected Branches

- **Default branch** (e.g. `master` or `main`): protected; changes only via Pull Request.
- **Feature work:** create a branch from the default, then open a PR:
  - `git checkout -b feat/my-feature` (or `fix/`, `docs/`, `chore/`)
  - Make changes, push, open PR. Merge after CI passes and review (if any).

**GitHub branch protection (recommended):**  
Repo → **Settings → Branches → Add rule** for `master` (or `main`):

- Require a pull request before merging (optional: require 1 approval).
- Require status checks to pass: e.g. `check`, `test`, `fmt`, `clippy`, `audit`, `build`.
- Do not allow bypassing the above (optional: allow maintainers to bypass).
- Save.

### Pull Requests
1. Fork the repository (or create a branch if you have write access)
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Run tests: `cargo test`
5. Run lints: `cargo clippy`
6. Push and create a PR targeting the default branch
7. Wait for CI to pass, then merge

### Adding a New Detection Rule

Adding a new rule to Velka involves 4 files. Here's the complete workflow:

#### Step 1: Define the rule in `src/engine/rules.rs`

Add an entry to the `RULES` static array:

```rust
Rule {
    id: "MY_PROVIDER_KEY",
    description: "My Provider API key detected",
    pattern: define_regex!(r"(?i)my_provider[_-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9]{32,})['\"]?"),
    severity: Severity::Mortal,        // Mortal = credential, Venial = PII
    expected_len: Some((32, 64)),       // expected token length range
    required_prefix: Some("mpk_"),     // known prefix (or None)
    charset: Some("alphanum"),          // "alphanum", "base64", "hex"
},
```

Key fields:
- `id`: SCREAMING_SNAKE_CASE, unique identifier
- `pattern`: regex that captures the secret value in group 1
- `severity`: `Mortal` for credentials/keys, `Venial` for PII
- `expected_len`, `required_prefix`, `charset`: used by ML classifier for structural scoring

#### Step 2: Add structural validation in `src/engine/structural_validators.rs`

If your rule has a check digit or structural constraint (like CPF, IBAN), add a match arm in `validate_for_rule`:

```rust
"MY_PROVIDER_KEY" => Some(validate_my_provider(snippet)),
```

Then implement the validation function. If the rule has no mathematical validation (just pattern matching), skip this step.

#### Step 3: Add integration tests in `tests/integration_test.rs`

Every rule needs at least 3 tests:

```rust
#[test]
fn test_my_provider_key_detected() {
    let code = r#"MY_PROVIDER_KEY=mpk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"#;
    let sins = scan_str(code).unwrap();
    assert!(!sins.is_empty());
    assert_eq!(sins[0].rule_id, "MY_PROVIDER_KEY");
}

#[test]
fn test_my_provider_key_invalid_rejected() {
    let code = r#"MY_PROVIDER_KEY=mpk_short"#;  // too short
    let sins = scan_str(code).unwrap();
    assert!(sins.is_empty());
}

#[test]
fn test_my_provider_key_placeholder_rejected() {
    let code = r#"MY_PROVIDER_KEY=mpk_00000000000000000000000000000000"#;
    let sins = scan_str(code).unwrap();
    assert!(sins.is_empty());
}
```

#### Step 4: Document in `README.md`

Add the new rule to the detection rules table in the README.

### Security Considerations
- Never log or store actual secret values
- Redaction must be enabled by default
- Error messages must not leak sensitive paths
- All paths must be validated before scanning

## Testing
- Unit tests: `cargo test`
- Integration tests: `cargo test --test '*'`
- Run Velka on itself: `cargo run -- scan .`

## Benchmarks
- Run all: `cargo bench`
- Run only cache benchmarks: `cargo bench scan_1000_files_cache`
- Run a specific bench (e.g. 1000 files): `cargo bench scan_1000_files`
- Benchmarks are in `benches/scan_bench.rs` (throughput with cache off; cache cold vs cache hit for 1000 files).

## Versioning

- **Single source of truth**: `version` in `Cargo.toml`.
- **Release tag**: must be `vX.Y.Z` (e.g. `v1.2.0`) and must match `Cargo.toml`. The publish workflow fails if they differ.
- **Semi-automatic bump** (optional): install [cargo-release](https://github.com/crate-ci/cargo-release), then:
  - `cargo release patch` (1.2.0 → 1.2.1) or `cargo release minor` (1.2.0 → 1.3.0) or `cargo release major`
  - This bumps `Cargo.toml`, commits, creates tag `vX.Y.Z`, and pushes. Then create a **GitHub Release** from that tag to trigger publish.

## Publishing to crates.io

### Automated (recommended)

1. In this repo: **Settings → Secrets and variables → Actions** → add secret `CRATES_IO_TOKEN` (create token at https://crates.io/settings/tokens).
2. Bump `version` in `Cargo.toml` (or use `cargo release patch`), commit and push.
3. Create a **GitHub Release** with tag `vX.Y.Z` (e.g. `v1.2.0`) **matching** the version in `Cargo.toml`.
4. The workflow **Publish to crates.io** runs on release, verifies tag ↔ Cargo.toml, then runs `cargo publish`. You can also trigger it manually: **Actions → Publish to crates.io → Run workflow**.

### Manual

1. Ensure all tests pass: `cargo test`
2. Run `cargo publish --dry-run` to verify the package
3. Log in: `cargo login` (get token from crates.io)
4. Publish: `cargo publish`
5. Docs are built automatically at https://docs.rs/velka

## Questions?

Open an issue for any questions or discussions.
