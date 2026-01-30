use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Mortal,
    Venial,
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
}

pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub pattern: &'static LazyLock<Regex>,
    pub severity: Severity,
}
