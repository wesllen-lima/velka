use std::collections::HashMap;
use std::sync::LazyLock;

use crate::domain::Sin;

static ENV_VAR_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("AWS_ACCESS_KEY", "AWS_ACCESS_KEY_ID");
    m.insert("AWS_SECRET_KEY", "AWS_SECRET_ACCESS_KEY");
    m.insert("GOOGLE_API_KEY", "GOOGLE_API_KEY");
    m.insert("GITHUB_TOKEN", "GITHUB_TOKEN");
    m.insert("STRIPE_SECRET", "STRIPE_SECRET_KEY");
    m.insert("SLACK_WEBHOOK", "SLACK_WEBHOOK_URL");
    m.insert("SENDGRID_API", "SENDGRID_API_KEY");
    m.insert("TWILIO_API", "TWILIO_API_KEY");
    m.insert("NPM_TOKEN", "NPM_TOKEN");
    m.insert("PYPI_TOKEN", "PYPI_API_TOKEN");
    m.insert("DISCORD_TOKEN", "DISCORD_TOKEN");
    m.insert("TELEGRAM_BOT", "TELEGRAM_BOT_TOKEN");
    m.insert("DB_CONNECTION_STRING", "DATABASE_URL");
    m.insert("HARDCODED_PASSWORD", "PASSWORD");
    m.insert("AZURE_STORAGE_KEY", "AZURE_STORAGE_KEY");
    m.insert("HEROKU_API_KEY", "HEROKU_API_KEY");
    m.insert("MAILGUN_API_KEY", "MAILGUN_API_KEY");
    m.insert("SQUARE_ACCESS_TOKEN", "SQUARE_ACCESS_TOKEN");
    m.insert("SQUARE_OAUTH_SECRET", "SQUARE_OAUTH_SECRET");
    m.insert("GENERIC_API_KEY", "API_KEY");
    m.insert("GENERIC_SECRET", "SECRET");
    m.insert("HIGH_ENTROPY", "SECRET_VALUE");
    m.insert("PRIVATE_KEY", "PRIVATE_KEY_PATH");
    m.insert("GCP_SERVICE_ACCOUNT", "GCP_SERVICE_ACCOUNT_JSON");
    m.insert("JWT_TOKEN", "JWT_SECRET");
    m
});

struct SnippetParts {
    decl: &'static str,
    var_name: String,
}

fn snippet_parts(snippet: &str) -> Option<SnippetParts> {
    let trimmed = snippet.trim();
    for (decl, prefix) in [
        ("const ", "const "),
        ("let ", "let "),
        ("var ", "var "),
        ("final ", "final "),
        ("val ", "val "),
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            if let Some(eq) = rest.find('=') {
                let name = rest[..eq].trim();
                if name.chars().all(|c| c.is_alphanumeric() || c == '_') && !name.is_empty() {
                    return Some(SnippetParts {
                        decl,
                        var_name: name.to_string(),
                    });
                }
            }
        }
    }
    if let Some(eq) = trimmed.find('=') {
        let lhs = trimmed[..eq].trim();
        if lhs
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == ' ')
            && !lhs.is_empty()
        {
            let name = lhs.split_whitespace().last().unwrap_or(lhs);
            if name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Some(SnippetParts {
                    decl: "",
                    var_name: name.to_string(),
                });
            }
        }
    }
    None
}

#[must_use]
pub fn env_var_for_rule(rule_id: &str) -> &'static str {
    ENV_VAR_MAP.get(rule_id).copied().unwrap_or("SECRET_NAME")
}

#[must_use]
pub fn suggest_remediation(sin: &Sin) -> String {
    let env_var = env_var_for_rule(&sin.rule_id);
    match snippet_parts(&sin.snippet) {
        Some(parts) => {
            if parts.decl.is_empty() {
                format!("{} = process.env.{env_var};", parts.var_name)
            } else {
                format!("{}{} = process.env.{env_var};", parts.decl, parts.var_name)
            }
        }
        None => format!("{env_var} = process.env.{env_var};"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Severity;

    fn sin_with(rule_id: &str, snippet: &str) -> Sin {
        Sin {
            path: "config.js".to_string(),
            line_number: 1,
            snippet: snippet.to_string(),
            context: Vec::new(),
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
    fn test_suggest_remediation_aws_access_key() {
        let sin = sin_with("AWS_ACCESS_KEY", r#"const AWS_KEY = "AKIA...";"#);
        let out = suggest_remediation(&sin);
        assert!(out.contains("process.env.AWS_ACCESS_KEY_ID"));
        assert!(out.contains("AWS_KEY"));
    }

    #[test]
    fn test_suggest_remediation_github_token() {
        let sin = sin_with("GITHUB_TOKEN", "const token = \"ghp_xxx\";");
        let out = suggest_remediation(&sin);
        assert!(out.contains("process.env.GITHUB_TOKEN"));
        assert!(out.contains("token"));
    }

    #[test]
    fn test_suggest_remediation_unknown_rule_fallback() {
        let sin = sin_with("UNKNOWN_RULE", "const x = \"secret\";");
        let out = suggest_remediation(&sin);
        assert!(out.contains("process.env.SECRET_NAME"));
    }

    #[test]
    fn test_env_var_for_rule_known() {
        assert_eq!(env_var_for_rule("AWS_ACCESS_KEY"), "AWS_ACCESS_KEY_ID");
        assert_eq!(env_var_for_rule("DB_CONNECTION_STRING"), "DATABASE_URL");
    }

    #[test]
    fn test_env_var_for_rule_unknown() {
        assert_eq!(env_var_for_rule("CUSTOM_RULE"), "SECRET_NAME");
    }
}
