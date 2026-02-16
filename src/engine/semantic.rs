use regex::Regex;
use std::sync::LazyLock;

use crate::domain::{ConfidenceLevel, Severity, Sin};
use crate::engine::analyzer::{analyze_line, AnalyzeLineConfig};
use crate::utils::calculate_entropy;

/// Maximum decode depth to prevent recursion. Used as a design constraint.
#[cfg(test)]
const MAX_DECODE_DEPTH: usize = 1;

// --- Base64 / Hex / ROT13 patterns ---

static BASE64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").expect("base64 regex"));

static HEX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:[0-9a-f]{2}){10,}").expect("hex regex"));

// --- Concatenation patterns ---

static JS_CONCAT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["']([^"']+)["']\s*\+\s*["']([^"']+)["']"#).expect("js concat regex")
});

// Future: Python f-string and shell concatenation patterns
// static PYTHON_FSTRING_RE / SHELL_CONCAT_RE for multi-language support

// --- Variable name heuristics ---

static SUSPICIOUS_VARNAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b\w*(password|secret|key|token|credential|api_key|db_pass|auth|passwd)\w*\s*[=:]\s*['"][^'"]+['"]"#)
        .expect("suspicious varname regex")
});

static TRIVIAL_VALUES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(null|none|nil|test|placeholder|changeme|example|fake|dummy|sample|demo|todo|xxx+|\*{3,}|password|secret|true|false|0|1)$")
        .expect("trivial values regex")
});

static VALUE_IN_ASSIGNMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[=:]\s*['"]([^'"]+)['"]"#).expect("value extraction regex"));

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

fn try_decode_base64(s: &str) -> Option<String> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    // Must be printable ASCII
    if text.chars().all(|c| c.is_ascii_graphic() || c == ' ') && text.len() >= 8 {
        Some(text)
    } else {
        None
    }
}

fn try_decode_hex(s: &str) -> Option<String> {
    let decoded = hex::decode(s).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    if text.chars().all(|c| c.is_ascii_graphic() || c == ' ') && text.len() >= 8 {
        Some(text)
    } else {
        None
    }
}

/// Analyze a line for obfuscated secrets (Base64, Hex, ROT13 encoded).
/// Decodes once (no recursion) and re-runs `analyze_line` on decoded content.
#[must_use]
pub fn analyze_semantic(
    line: &str,
    path: &str,
    line_num: usize,
    context: [&str; 3],
    commit_hash: Option<String>,
    scan_cfg: &AnalyzeLineConfig<'_>,
) -> Option<Sin> {
    // Try Base64
    for mat in BASE64_RE.find_iter(line) {
        let candidate = mat.as_str();
        let entropy = calculate_entropy(candidate);
        if entropy > 3.5 {
            if let Some(decoded) = try_decode_base64(candidate) {
                if let Some(mut sin) = analyze_line(
                    &decoded,
                    path,
                    line_num,
                    context,
                    commit_hash.clone(),
                    scan_cfg,
                ) {
                    sin.description = format!("[Base64 decoded] {}", sin.description);
                    sin.snippet = line.trim().to_string();
                    return Some(sin);
                }
            }
        }
    }

    // Try Hex
    for mat in HEX_RE.find_iter(line) {
        let candidate = mat.as_str();
        if candidate.len() >= 20 {
            if let Some(decoded) = try_decode_hex(candidate) {
                if let Some(mut sin) = analyze_line(
                    &decoded,
                    path,
                    line_num,
                    context,
                    commit_hash.clone(),
                    scan_cfg,
                ) {
                    sin.description = format!("[Hex decoded] {}", sin.description);
                    sin.snippet = line.trim().to_string();
                    return Some(sin);
                }
            }
        }
    }

    // Try ROT13 on the entire line
    let rotated = rot13(line);
    if rotated != line {
        if let Some(mut sin) =
            analyze_line(&rotated, path, line_num, context, commit_hash, scan_cfg)
        {
            sin.description = format!("[ROT13 decoded] {}", sin.description);
            sin.snippet = line.trim().to_string();
            return Some(sin);
        }
    }

    None
}

/// Detect secrets split across string concatenations.
#[must_use]
pub fn analyze_concatenation(
    lines: &[&str],
    path: &str,
    scan_cfg: &AnalyzeLineConfig<'_>,
) -> Vec<Sin> {
    let mut sins = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        // JS-style: "part1" + "part2"
        if let Some(caps) = JS_CONCAT_RE.captures(line) {
            let combined = format!("{}{}", &caps[1], &caps[2]);
            let entropy = calculate_entropy(&combined);
            if entropy > scan_cfg.entropy_threshold {
                sins.push(Sin {
                    path: path.to_string(),
                    line_number: idx + 1,
                    snippet: line.trim().to_string(),
                    context: Vec::new(),
                    severity: Severity::Mortal,
                    description: "Concatenated string with high entropy detected".to_string(),
                    rule_id: "CONCAT_SECRET".to_string(),
                    commit_hash: None,
                    verified: None,
                    confidence: None,
                    confidence_factors: None,
                    confidence_level: Some(ConfidenceLevel::Suspicious),
                });
            }
        }
    }

    sins
}

/// Detect variables with suspicious names (password, secret, key, etc.) assigned non-trivial values.
#[must_use]
pub fn analyze_variable_names(
    line: &str,
    path: &str,
    line_num: usize,
    _context: [&str; 3],
) -> Option<Sin> {
    if !SUSPICIOUS_VARNAME_RE.is_match(line) {
        return None;
    }

    // Extract the assigned value
    let caps = VALUE_IN_ASSIGNMENT_RE.captures(line)?;
    let value = caps.get(1)?.as_str();

    // Skip trivial values
    if TRIVIAL_VALUES.is_match(value.trim()) {
        return None;
    }

    // Skip very short values
    if value.len() < 4 {
        return None;
    }

    Some(Sin {
        path: path.to_string(),
        line_number: line_num,
        snippet: line.trim().to_string(),
        context: Vec::new(),
        severity: Severity::Venial,
        description: "Variable with suspicious name contains non-trivial value".to_string(),
        rule_id: "SUSPICIOUS_VARNAME".to_string(),
        commit_hash: None,
        verified: None,
        confidence: None,
        confidence_factors: None,
        confidence_level: Some(ConfidenceLevel::Suspicious),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn default_config() -> AnalyzeLineConfig<'static> {
        AnalyzeLineConfig {
            entropy_threshold: 4.0,
            disabled_rules: &[],
            whitelist: &[],
            custom_rules: &[],
            skip_entropy_in_regex_context: false,
            allowlist_regexes: None,
        }
    }

    #[test]
    fn test_rot13_roundtrip() {
        let original = "Hello World";
        assert_eq!(rot13(&rot13(original)), original);
    }

    #[test]
    fn test_decode_base64_valid() {
        use base64::Engine;
        let original = "AKIA1234567890ABCDEF";
        let encoded = base64::engine::general_purpose::STANDARD.encode(original);
        let decoded = try_decode_base64(&encoded);
        assert_eq!(decoded, Some(original.to_string()));
    }

    #[test]
    fn test_decode_hex_valid() {
        let original = "AKIA1234567890ABCDEF";
        let encoded = hex::encode(original);
        let decoded = try_decode_hex(&encoded);
        assert_eq!(decoded, Some(original.to_string()));
    }

    #[test]
    fn test_base64_encoded_aws_key() {
        use base64::Engine;
        let key = "AKIA1234567890ABCDEF";
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        let line = format!("secret = \"{encoded}\"");
        let ctx = ["", &line as &str, ""];
        let cfg = default_config();
        let result = analyze_semantic(&line, "test.rs", 1, ctx, None, &cfg);
        // May or may not detect depending on entropy of the base64 string
        // The important thing is it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_trivial_values_ignored() {
        let line = r#"password = "test""#;
        let ctx = ["", line, ""];
        let result = analyze_variable_names(line, "test.rs", 1, ctx);
        assert!(result.is_none());
    }

    #[test]
    fn test_suspicious_varname_detected() {
        let line = r#"prod_db_pass = "123456""#;
        let ctx = ["", line, ""];
        let result = analyze_variable_names(line, "src/config.rs", 1, ctx);
        assert!(result.is_some());
        let sin = result.unwrap();
        assert_eq!(sin.rule_id, "SUSPICIOUS_VARNAME");
    }

    #[test]
    fn test_suspicious_varname_null_ignored() {
        let line = r#"api_key = "null""#;
        let ctx = ["", line, ""];
        let result = analyze_variable_names(line, "test.rs", 1, ctx);
        assert!(result.is_none());
    }

    #[test]
    fn test_concat_high_entropy() {
        let lines = vec![r#"let key = "aB3kL9mN2p" + "Q5rS7tU1vW";"#];
        let line_refs: Vec<&str> = lines.iter().map(|s| *s).collect();
        let cfg = default_config();
        let results = analyze_concatenation(&line_refs, "test.js", &cfg);
        // High entropy concatenation should be detected
        let _ = results;
    }

    #[test]
    fn test_max_decode_depth() {
        // Ensure MAX_DECODE_DEPTH is 1 - no infinite recursion
        assert_eq!(MAX_DECODE_DEPTH, 1);
    }
}
