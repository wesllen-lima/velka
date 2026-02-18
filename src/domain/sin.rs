//! Core domain types for scan findings.
//!
//! A [`Sin`] represents a single secret or PII finding, including its
//! location, matched rule, severity and optional ML confidence score.
//! [`Rule`] describes a detection pattern with structural metadata used
//! by the ML classifier and structural validators.

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

/// Risk level of a verified credential, from least to most damaging.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Read-only access (list buckets, read metrics).
    ReadOnly,
    /// Read + write on some resources.
    ReadWrite,
    /// Full administrative control over a service.
    Administrative,
    /// Cross-service blast radius — can cause irreversible damage (e.g. `AdministratorAccess`).
    Catastrophic,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "ReadOnly"),
            Self::ReadWrite => write!(f, "ReadWrite"),
            Self::Administrative => write!(f, "Administrative"),
            Self::Catastrophic => write!(f, "CATASTROPHIC"),
        }
    }
}

/// Rich metadata returned by live credential verification.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationDetail {
    /// Whether the credential was confirmed active against the external service.
    pub is_active: bool,
    /// Identity associated with the credential (AWS ARN, GitHub username, etc.).
    pub identity: Option<String>,
    /// Permission scopes / IAM policies attached to this credential.
    pub permissions: Vec<String>,
    /// Computed blast-radius level.
    pub risk_level: RiskLevel,
}

/// Severity of a finding.
///
/// * `Mortal` — high-impact credentials (AWS keys, private keys, tokens).
/// * `Venial` — lower-impact PII or informational matches (CPF, emails).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Mortal,
    Venial,
}

/// Type-safe confidence classification derived from structural validation
/// and ML ensemble scoring. Ord derivation guarantees: Info < Suspicious < Critical.
/// A `match` on this enum is exhaustive — the compiler prevents treating Info as Critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    Info,
    Suspicious,
    Critical,
}

impl ConfidenceLevel {
    /// Derive level from a numeric confidence score.
    #[must_use]
    pub fn from_score(score: f32) -> Self {
        if score >= 0.75 {
            Self::Critical
        } else if score >= 0.4 {
            Self::Suspicious
        } else {
            Self::Info
        }
    }
}

impl std::fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Suspicious => write!(f, "SUSPICIOUS"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single secret or PII finding produced by the scanner.
#[derive(Debug, Clone, Serialize)]
pub struct Sin {
    /// File path where the finding was detected.
    pub path: String,
    /// 1-based line number within the file.
    pub line_number: usize,
    /// The matched secret or PII value (may be redacted in output).
    pub snippet: String,
    /// Surrounding lines for context.
    pub context: Vec<String>,
    /// Severity classification of the finding.
    pub severity: Severity,
    /// Human-readable description of the matched rule.
    pub description: String,
    /// Identifier of the rule that triggered this finding (e.g. `"AWS_ACCESS_KEY"`).
    #[serde(rename = "rule_id")]
    pub rule_id: String,
    /// Git commit hash when found via history scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<String>,
    /// Whether the secret was verified against an external service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    /// ML ensemble confidence score in `[0.0, 1.0]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    /// Individual factor contributions from the ML classifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_factors: Option<Vec<String>>,
    /// Derived confidence level (Info / Suspicious / Critical).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_level: Option<ConfidenceLevel>,
    /// Rich verification metadata (populated when `--verify` is used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_detail: Option<VerificationDetail>,
}

/// A detection rule with its regex pattern and structural metadata.
pub struct Rule {
    /// Unique identifier (e.g. `"AWS_ACCESS_KEY"`, `"BRAZILIAN_CPF"`).
    pub id: &'static str,
    /// Human-readable description shown in findings.
    pub description: &'static str,
    /// Compiled regex used to match candidates.
    pub pattern: &'static LazyLock<Regex>,
    /// Severity classification.
    pub severity: Severity,
    /// Expected length range (min, max) for the secret value.
    pub expected_len: Option<(usize, usize)>,
    /// Required prefix for structural validation (e.g. "AKIA", "ghp_").
    pub required_prefix: Option<&'static str>,
    /// Character set hint: "alphanum", "base64", "hex", or None.
    pub charset: Option<&'static str>,
}
