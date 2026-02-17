//! Baseline tracking and drift detection for CI/CD integration.
//!
//! Saves a fingerprint of current findings so that subsequent scans can
//! report only *new* regressions (`diff`) or confirm the baseline unchanged.
//!
//! Storage: `~/.velka/baseline.json` (overridable with `--baseline-file`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::Sin;

const BASELINE_VERSION: &str = "1";

// ── Data types ─────────────────────────────────────────────────────────────

/// Fingerprint of a single finding, stable across refactors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BaselineEntry {
    /// File path (relative where possible).
    pub path: String,
    /// 1-based line number.
    pub line_number: usize,
    /// Rule that triggered the finding.
    pub rule_id: String,
    /// SHA-256 of the raw snippet (first 64 chars), hex-encoded.
    pub snippet_hash: String,
}

impl BaselineEntry {
    fn from_sin(sin: &Sin) -> Self {
        let snippet_trimmed = sin.snippet.trim();
        let truncated = &snippet_trimmed[..snippet_trimmed.len().min(64)];
        let mut hasher = Sha256::new();
        hasher.update(truncated.as_bytes());
        let snippet_hash = hex::encode(hasher.finalize());

        Self {
            path: sin.path.clone(),
            line_number: sin.line_number,
            rule_id: sin.rule_id.clone(),
            snippet_hash,
        }
    }
}

/// Persisted baseline file.
#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    /// Schema version for forward-compat.
    pub version: String,
    /// ISO-8601 timestamp when the baseline was saved.
    pub created_at: String,
    /// Total number of findings at save time.
    pub total_findings: usize,
    /// Fingerprints of all findings.
    pub entries: Vec<BaselineEntry>,
}

/// Result of comparing current findings against a saved baseline.
#[derive(Debug)]
pub struct BaselineDiff {
    /// Findings present now but not in baseline (regressions).
    pub new_findings: Vec<BaselineEntry>,
    /// Findings in baseline but not present now (resolved).
    pub removed_findings: Vec<BaselineEntry>,
    /// Findings in both (unchanged).
    pub unchanged_count: usize,
}

impl BaselineDiff {
    #[must_use]
    pub fn has_regressions(&self) -> bool {
        !self.new_findings.is_empty()
    }
}

// ── Storage ────────────────────────────────────────────────────────────────

/// Returns the default baseline path: `~/.velka/baseline.json`.
#[must_use]
pub fn default_baseline_path() -> PathBuf {
    directories::BaseDirs::new().map_or_else(
        || PathBuf::from(".velka_baseline.json"),
        |d| d.home_dir().join(".velka").join("baseline.json"),
    )
}

/// Save `findings` as the new baseline.
pub fn save(findings: &[Sin], path: Option<&Path>) -> Result<()> {
    let dest = path.map_or_else(default_baseline_path, PathBuf::from);

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Cannot create baseline directory: {}", parent.display()))?;
    }

    let entries: Vec<BaselineEntry> = findings.iter().map(BaselineEntry::from_sin).collect();
    let baseline = Baseline {
        version: BASELINE_VERSION.to_string(),
        created_at: Utc::now().to_rfc3339(),
        total_findings: entries.len(),
        entries,
    };

    let json = serde_json::to_string_pretty(&baseline).context("Failed to serialize baseline")?;
    std::fs::write(&dest, json)
        .with_context(|| format!("Cannot write baseline to {}", dest.display()))?;

    Ok(())
}

/// Load the saved baseline.
pub fn load(path: Option<&Path>) -> Result<Baseline> {
    let src = path.map_or_else(default_baseline_path, PathBuf::from);

    let raw = std::fs::read_to_string(&src).with_context(|| {
        format!(
            "No baseline found at {}. Run `velka baseline save` first.",
            src.display()
        )
    })?;

    serde_json::from_str(&raw).with_context(|| "Baseline file is corrupt or has unknown format")
}

// ── Diff ───────────────────────────────────────────────────────────────────

/// Compare `current` findings against a saved `baseline`.
#[must_use]
pub fn diff(current: &[Sin], baseline: &Baseline) -> BaselineDiff {
    let current_set: HashSet<BaselineEntry> = current.iter().map(BaselineEntry::from_sin).collect();
    let baseline_set: HashSet<BaselineEntry> = baseline.entries.iter().cloned().collect();

    let new_findings: Vec<BaselineEntry> = current_set.difference(&baseline_set).cloned().collect();

    let removed_findings: Vec<BaselineEntry> =
        baseline_set.difference(&current_set).cloned().collect();

    let unchanged_count = current_set.intersection(&baseline_set).count();

    BaselineDiff {
        new_findings,
        removed_findings,
        unchanged_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Severity;

    fn make_sin(rule_id: &str, path: &str, line: usize, snippet: &str) -> Sin {
        Sin {
            path: path.to_string(),
            line_number: line,
            snippet: snippet.to_string(),
            context: vec![],
            severity: Severity::Mortal,
            description: String::new(),
            rule_id: rule_id.to_string(),
            commit_hash: None,
            verified: None,
            confidence: None,
            confidence_factors: None,
            confidence_level: None,
            verification_detail: None,
        }
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");

        let sins = vec![make_sin("AWS_ACCESS_KEY", "src/main.rs", 10, "AKIA123")];
        save(&sins, Some(&path)).unwrap();

        let loaded = load(Some(&path)).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].rule_id, "AWS_ACCESS_KEY");
        assert_eq!(loaded.version, "1");
    }

    #[test]
    fn test_diff_detects_new_finding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");

        let old = vec![make_sin("AWS_ACCESS_KEY", "src/main.rs", 10, "AKIA123")];
        save(&old, Some(&path)).unwrap();
        let baseline = load(Some(&path)).unwrap();

        let current = vec![
            make_sin("AWS_ACCESS_KEY", "src/main.rs", 10, "AKIA123"),
            make_sin("GITHUB_TOKEN", "src/api.rs", 42, "ghp_abc123"),
        ];

        let result = diff(&current, &baseline);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.new_findings[0].rule_id, "GITHUB_TOKEN");
        assert_eq!(result.removed_findings.len(), 0);
        assert_eq!(result.unchanged_count, 1);
    }

    #[test]
    fn test_diff_detects_removed_finding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");

        let old = vec![
            make_sin("AWS_ACCESS_KEY", "src/main.rs", 10, "AKIA123"),
            make_sin("STRIPE_SECRET", "src/pay.rs", 5, "sk_live_abc"),
        ];
        save(&old, Some(&path)).unwrap();
        let baseline = load(Some(&path)).unwrap();

        let current = vec![make_sin("AWS_ACCESS_KEY", "src/main.rs", 10, "AKIA123")];
        let result = diff(&current, &baseline);
        assert_eq!(result.removed_findings.len(), 1);
        assert!(!result.has_regressions());
    }

    #[test]
    fn test_diff_no_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");

        let sins = vec![make_sin("AWS_ACCESS_KEY", "src/main.rs", 10, "AKIA123")];
        save(&sins, Some(&path)).unwrap();
        let baseline = load(Some(&path)).unwrap();

        let result = diff(&sins, &baseline);
        assert!(!result.has_regressions());
        assert_eq!(result.unchanged_count, 1);
    }
}
