use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

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

#[derive(Debug, Clone, Serialize)]
pub struct Sin {
    pub path: String,
    pub line_number: usize,
    pub snippet: String,
    pub context: Vec<String>,
    pub severity: Severity,
    pub description: String,
    #[serde(rename = "rule_id")]
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_factors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_level: Option<ConfidenceLevel>,
}

pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub pattern: &'static LazyLock<Regex>,
    pub severity: Severity,
}
