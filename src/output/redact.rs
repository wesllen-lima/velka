use crate::engine::RULES;
use crate::utils::calculate_entropy;

#[derive(Debug, Clone)]
pub struct RedactionConfig {
    pub enabled: bool,
    pub visible_chars: usize,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            visible_chars: 4,
        }
    }
}

#[must_use]
pub fn redact_secret(secret: &str, config: &RedactionConfig) -> String {
    if !config.enabled {
        return secret.to_string();
    }

    let min_length = config.visible_chars * 2 + 4;
    if secret.len() < min_length {
        return "[REDACTED]".to_string();
    }

    let prefix = &secret[..config.visible_chars];
    let suffix = &secret[secret.len() - config.visible_chars..];
    format!("{prefix}****{suffix}")
}

#[must_use]
pub fn redact_line(line: &str, rule_id: &str, config: &RedactionConfig) -> String {
    if !config.enabled {
        return line.to_string();
    }

    if rule_id == "HIGH_ENTROPY" {
        return redact_high_entropy_strings(line, config);
    }

    for rule in RULES {
        if rule.id == rule_id {
            if let Some(mat) = rule.pattern.find(line) {
                let matched = mat.as_str();
                let redacted = redact_secret(matched, config);
                return line.replace(matched, &redacted);
            }
        }
    }

    line.to_string()
}

fn redact_high_entropy_strings(line: &str, config: &RedactionConfig) -> String {
    let mut result = line.to_string();
    let mut in_quote = false;
    let mut quote_char = ' ';
    let mut start = 0;

    for (i, ch) in line.char_indices() {
        if !in_quote && (ch == '"' || ch == '\'') {
            in_quote = true;
            quote_char = ch;
            start = i + 1;
        } else if in_quote && ch == quote_char {
            let content = &line[start..i];
            if content.len() > 20 && calculate_entropy(content) > 4.5 {
                let redacted = redact_secret(content, config);
                result = result.replace(content, &redacted);
            }
            in_quote = false;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_secret_enabled() {
        let config = RedactionConfig::default();
        assert_eq!(
            redact_secret("AKIAIOSFODNN7EXAMPLE", &config),
            "AKIA****MPLE"
        );
    }

    #[test]
    fn test_redact_secret_disabled() {
        let config = RedactionConfig {
            enabled: false,
            visible_chars: 4,
        };
        assert_eq!(
            redact_secret("AKIAIOSFODNN7EXAMPLE", &config),
            "AKIAIOSFODNN7EXAMPLE"
        );
    }

    #[test]
    fn test_redact_short_secret() {
        let config = RedactionConfig::default();
        assert_eq!(redact_secret("short", &config), "[REDACTED]");
    }
}
