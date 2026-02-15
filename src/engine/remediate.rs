use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;

use crate::domain::Sin;

static RE_QUOTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[=:]\s*["']([^"']+)["']"#).expect("invalid regex"));
static RE_UNQUOTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[=:]\s*(\S+)").expect("invalid regex"));

#[derive(Debug, Clone)]
pub struct PlaceholderResult {
    pub file_path: String,
    pub line_number: usize,
    pub original_snippet: String,
    pub placeholder: String,
    pub replaced: bool,
}

/// Derive an env-var style placeholder from a `rule_id`.
/// Example: `AWS_ACCESS_KEY` at line 10 in `config.py` -> `{{env.AWS_ACCESS_KEY}}`
#[must_use]
pub fn derive_placeholder(rule_id: &str) -> String {
    format!("{{{{env.{rule_id}}}}}")
}

/// Replace the secret value in a single line with the placeholder.
/// Returns the modified line and whether a replacement occurred.
fn replace_secret_in_line(line: &str, snippet: &str, placeholder: &str) -> (String, bool) {
    if snippet.is_empty() {
        return (line.to_string(), false);
    }

    // Extract the actual secret value from the snippet (the part after = or : delimiters)
    let secret_value = extract_secret_value(snippet);
    if secret_value.is_empty() {
        return (line.to_string(), false);
    }

    if line.contains(&secret_value) {
        let new_line = line.replacen(&secret_value, placeholder, 1);
        (new_line, true)
    } else {
        (line.to_string(), false)
    }
}

/// Extract the raw secret value from a snippet like `API_KEY="sk-abc123"` -> `sk-abc123`
fn extract_secret_value(snippet: &str) -> String {
    // Try quoted value first: ="value" or ='value'
    if let Some(cap) = RE_QUOTED.captures(snippet) {
        return cap[1].to_string();
    }

    // Unquoted: = value (no spaces in value)
    if let Some(cap) = RE_UNQUOTED.captures(snippet) {
        return cap[1].to_string();
    }

    // Fallback: the whole snippet trimmed (for patterns like bare tokens)
    snippet.trim().to_string()
}

/// Apply placeholder injection to a file for a given sin.
pub fn inject_placeholder(sin: &Sin, dry_run: bool) -> Result<PlaceholderResult> {
    let placeholder = derive_placeholder(&sin.rule_id);
    let file_path = Path::new(&sin.path);

    let content = fs::read_to_string(file_path).with_context(|| format!("Read {}", sin.path))?;
    let lines: Vec<&str> = content.lines().collect();

    let line_idx = sin.line_number.saturating_sub(1);

    if line_idx >= lines.len() {
        return Ok(PlaceholderResult {
            file_path: sin.path.clone(),
            line_number: sin.line_number,
            original_snippet: sin.snippet.clone(),
            placeholder,
            replaced: false,
        });
    }

    let (new_line, replaced) = replace_secret_in_line(lines[line_idx], &sin.snippet, &placeholder);

    if replaced && !dry_run {
        let mut new_lines: Vec<String> =
            lines.iter().map(std::string::ToString::to_string).collect();
        new_lines[line_idx] = new_line;

        let new_content = new_lines.join("\n");
        // Preserve trailing newline if original had one
        let final_content = if content.ends_with('\n') {
            format!("{new_content}\n")
        } else {
            new_content
        };

        fs::write(file_path, final_content).with_context(|| format!("Write {}", sin.path))?;
    }

    Ok(PlaceholderResult {
        file_path: sin.path.clone(),
        line_number: sin.line_number,
        original_snippet: sin.snippet.clone(),
        placeholder,
        replaced,
    })
}

/// Batch placeholder injection for multiple sins, returning results.
#[must_use]
pub fn inject_placeholders(sins: &[Sin], dry_run: bool) -> Vec<PlaceholderResult> {
    sins.iter()
        .filter_map(|sin| inject_placeholder(sin, dry_run).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Severity;

    #[test]
    fn test_derive_placeholder() {
        assert_eq!(
            derive_placeholder("AWS_ACCESS_KEY"),
            "{{env.AWS_ACCESS_KEY}}"
        );
        assert_eq!(derive_placeholder("DB_PASSWORD"), "{{env.DB_PASSWORD}}");
    }

    #[test]
    fn test_extract_secret_value() {
        assert_eq!(extract_secret_value(r#"API_KEY="sk-abc123""#), "sk-abc123");
        assert_eq!(extract_secret_value("PASSWORD='hunter2'"), "hunter2");
        assert_eq!(extract_secret_value("TOKEN=abcdef"), "abcdef");
    }

    #[test]
    fn test_replace_secret_in_line() {
        let line = r#"API_KEY="sk-abc123""#;
        let snippet = r#"API_KEY="sk-abc123""#;
        let (result, replaced) = replace_secret_in_line(line, snippet, "{{env.API_KEY}}");
        assert!(replaced);
        assert_eq!(result, r#"API_KEY="{{env.API_KEY}}""#);
    }

    #[test]
    fn test_inject_placeholder_dry_run() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("config.env");
        std::fs::write(&file, "DB_PASSWORD=\"hunter2\"\nOTHER=safe\n").unwrap();

        let sin = Sin {
            path: file.to_string_lossy().to_string(),
            line_number: 1,
            snippet: "DB_PASSWORD=\"hunter2\"".to_string(),
            context: vec![],
            severity: Severity::Mortal,
            description: "Hardcoded password".to_string(),
            rule_id: "DB_PASSWORD".to_string(),
            commit_hash: None,
            verified: None,
            confidence: None,
            confidence_factors: None,
        };

        let result = inject_placeholder(&sin, true).unwrap();
        assert!(result.replaced);
        // dry_run: file should be unchanged
        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.contains("hunter2"));
    }

    #[test]
    fn test_inject_placeholder_write() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("config.env");
        std::fs::write(&file, "DB_PASSWORD=\"hunter2\"\nOTHER=safe\n").unwrap();

        let sin = Sin {
            path: file.to_string_lossy().to_string(),
            line_number: 1,
            snippet: "DB_PASSWORD=\"hunter2\"".to_string(),
            context: vec![],
            severity: Severity::Mortal,
            description: "Hardcoded password".to_string(),
            rule_id: "DB_PASSWORD".to_string(),
            commit_hash: None,
            verified: None,
            confidence: None,
            confidence_factors: None,
        };

        let result = inject_placeholder(&sin, false).unwrap();
        assert!(result.replaced);
        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.contains("{{env.DB_PASSWORD}}"));
        assert!(!content.contains("hunter2"));
    }
}
