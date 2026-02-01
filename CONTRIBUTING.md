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

### Adding New Rules
1. Add the rule to `src/engine/rules.rs`
2. Add tests in `tests/` directory
3. Update documentation if needed
4. Test with real-world examples

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
