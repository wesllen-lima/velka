use regex::Regex;
use std::sync::LazyLock;
use std::time::Duration;

use crate::domain::Sin;

static AWS_KEY_PATTERN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^(AKIA|ASIA)[A-Z0-9]{16}$").ok());

static HTTP_CLIENT: LazyLock<Option<reqwest::blocking::Client>> = LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        .user_agent(format!("velka/{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(3))
        .build()
        .ok()
});

static GITHUB_TOKEN_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").ok());
static STRIPE_SECRET_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}").ok());
static SENDGRID_API_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}").ok());
static SLACK_WEBHOOK_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+").ok()
});

pub fn verify(sin: &mut Sin) {
    let verified = match sin.rule_id.as_str() {
        "GITHUB_TOKEN" => verify_github(&sin.snippet),
        "STRIPE_SECRET" => verify_stripe(&sin.snippet),
        "SENDGRID_API" => verify_sendgrid(&sin.snippet),
        "SLACK_WEBHOOK" => verify_slack_webhook(&sin.snippet),
        _ => None,
    };
    sin.verified = verified;
}

fn verify_github(snippet: &str) -> Option<bool> {
    let re = GITHUB_TOKEN_RE.as_ref()?;
    let token = re.find(snippet)?.as_str();
    let client = HTTP_CLIENT.as_ref()?;
    let resp = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .ok()?;
    Some(resp.status().is_success())
}

fn verify_stripe(snippet: &str) -> Option<bool> {
    let re = STRIPE_SECRET_RE.as_ref()?;
    let secret = re.find(snippet)?.as_str();
    let client = HTTP_CLIENT.as_ref()?;
    let resp = client
        .get("https://api.stripe.com/v1/balance")
        .basic_auth(secret, Some(""))
        .send()
        .ok()?;
    Some(resp.status().is_success())
}

fn verify_sendgrid(snippet: &str) -> Option<bool> {
    let re = SENDGRID_API_RE.as_ref()?;
    let key = re.find(snippet)?.as_str();
    let client = HTTP_CLIENT.as_ref()?;
    let resp = client
        .get("https://api.sendgrid.com/v3/user/profile")
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .ok()?;
    Some(resp.status().is_success())
}

fn verify_slack_webhook(snippet: &str) -> Option<bool> {
    let re = SLACK_WEBHOOK_RE.as_ref()?;
    let url = re.find(snippet)?.as_str();
    let client = HTTP_CLIENT.as_ref()?;
    let resp = client
        .post(url)
        .json(&serde_json::json!({"text": "velka verification"}))
        .send()
        .ok()?;
    Some(resp.status().is_success())
}

fn path_suggests_test(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.contains("/tests/")
        || normalized.contains("/test/")
        || normalized.contains("/__tests__/")
        || normalized.contains("/spec/")
        || normalized.contains(".spec.")
        || normalized.contains("_test.")
        || normalized.contains(".test.")
}

fn path_suggests_config(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    let p = std::path::Path::new(&path_lower);
    let ext = p.extension();
    ext.is_some_and(|e| e.eq_ignore_ascii_case("env"))
        || path_lower.contains(".config.")
        || ext.is_some_and(|e| e.eq_ignore_ascii_case("yml"))
        || ext.is_some_and(|e| e.eq_ignore_ascii_case("yaml"))
        || path_lower.contains("/.env")
}

fn validate_structure(snippet: &str, rule_id: &str) -> Option<f32> {
    match rule_id {
        "JWT_TOKEN" => {
            let parts: Vec<&str> = snippet.split('.').collect();
            if parts.len() == 3 {
                let valid = parts.iter().all(|p| {
                    p.chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                });
                if valid {
                    return Some(0.2);
                }
            }
            Some(-0.3)
        }
        "AWS_ACCESS_KEY" => {
            if let Some(re) = AWS_KEY_PATTERN.as_ref() {
                if re.is_match(snippet) {
                    return Some(0.25);
                }
            }
            Some(-0.2)
        }
        _ => None,
    }
}

pub fn enhance_confidence_with_context(sin: &mut Sin, lines: &[&str], line_idx: usize) {
    let start = line_idx.saturating_sub(5);
    let end = (line_idx + 6).min(lines.len());
    let context_lines = &lines[start..end];

    let mut context_score = 0.0_f32;
    let mut context_factors = Vec::new();

    for (i, line) in context_lines.iter().enumerate() {
        if i == line_idx - start {
            continue;
        }
        let lower = line.to_lowercase();
        if lower.contains("api_key")
            || lower.contains("api_url")
            || lower.contains("secret")
            || lower.contains("token")
            || lower.contains("password")
        {
            context_score += 0.15;
            context_factors.push(format!("+0.15 nearby_keyword_L{}", start + i + 1));
            break;
        }
    }

    let current_line = lines.get(line_idx).unwrap_or(&"");
    if current_line.contains('=') || current_line.contains(':') {
        context_score += 0.1;
        context_factors.push("+0.1 assignment_context".to_string());
    }

    if context_score > 0.0 {
        let current_conf = sin.confidence.unwrap_or(0.5);
        sin.confidence = Some((current_conf + context_score).clamp(0.0, 1.0));
        if let Some(ref mut factors) = sin.confidence_factors {
            factors.extend(context_factors);
        } else {
            sin.confidence_factors = Some(context_factors);
        }
    }
}

pub fn compute_confidence(sin: &mut Sin) {
    let mut score = 0.5_f32;
    let mut factors = Vec::new();

    if let Some(boost) = validate_structure(&sin.snippet, &sin.rule_id) {
        score += boost;
        if boost > 0.0 {
            factors.push(format!("+{boost:.2} valid_structure"));
        } else {
            factors.push(format!("{boost:.2} invalid_structure"));
        }
    }

    if sin.verified == Some(true) {
        score += 0.3;
        factors.push("+0.3 verified_active".to_string());
    }
    if path_suggests_config(&sin.path) {
        score += 0.1;
        factors.push("+0.1 config_file".to_string());
    }
    if path_suggests_test(&sin.path) {
        score -= 0.2;
        factors.push("-0.2 test_file_path".to_string());
    }
    score = score.clamp(0.0, 1.0);
    sin.confidence = Some(score);
    sin.confidence_factors = if factors.is_empty() {
        None
    } else {
        Some(factors)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Severity;

    fn make_sin(rule_id: &str, path: &str, snippet: &str) -> Sin {
        Sin {
            path: path.to_string(),
            line_number: 1,
            snippet: snippet.to_string(),
            context: vec![],
            severity: Severity::Mortal,
            description: "test".to_string(),
            rule_id: rule_id.to_string(),
            commit_hash: None,
            verified: None,
            confidence: None,
            confidence_factors: None,
        }
    }

    #[test]
    fn test_compute_confidence_aws_valid_structure() {
        let mut sin = make_sin("AWS_ACCESS_KEY", "src/main.rs", "AKIA1234567890ABCDEF");
        compute_confidence(&mut sin);
        let conf = sin.confidence.unwrap();
        assert!(conf > 0.7, "Expected > 0.7, got {}", conf);
    }

    #[test]
    fn test_compute_confidence_test_file_penalty() {
        let mut sin = make_sin(
            "AWS_ACCESS_KEY",
            "project/tests/scan_test.rs",
            "AKIA1234567890ABCDEF",
        );
        compute_confidence(&mut sin);
        let conf = sin.confidence.unwrap();
        assert!(
            conf < 0.7,
            "Test file should reduce confidence, got {}",
            conf
        );
    }

    #[test]
    fn test_compute_confidence_config_file_boost() {
        let mut sin = make_sin("AWS_ACCESS_KEY", "config.env", "AKIA1234567890ABCDEF");
        compute_confidence(&mut sin);
        let conf = sin.confidence.unwrap();
        assert!(
            conf > 0.8,
            "Config file should boost confidence, got {}",
            conf
        );
    }

    #[test]
    fn test_compute_confidence_verified_boost() {
        let mut sin = make_sin("GITHUB_TOKEN", "src/main.rs", "ghp_abc123");
        sin.verified = Some(true);
        compute_confidence(&mut sin);
        let conf = sin.confidence.unwrap();
        assert!(
            conf >= 0.8,
            "Verified should boost confidence, got {}",
            conf
        );
    }

    #[test]
    fn test_compute_confidence_factors_populated() {
        let mut sin = make_sin("AWS_ACCESS_KEY", "config.env", "AKIA1234567890ABCDEF");
        compute_confidence(&mut sin);
        assert!(sin.confidence_factors.is_some());
    }

    #[test]
    fn test_enhance_confidence_with_nearby_keywords() {
        let mut sin = make_sin("AWS_ACCESS_KEY", "src/main.rs", "AKIA1234567890ABCDEF");
        sin.confidence = Some(0.5);
        let lines = vec![
            "// configuration",
            "let api_key = get_key();",
            "let key = \"AKIA1234567890ABCDEF\";",
            "process(key);",
        ];
        enhance_confidence_with_context(&mut sin, &lines, 2);
        let conf = sin.confidence.unwrap();
        assert!(
            conf > 0.5,
            "Nearby keyword should boost confidence, got {}",
            conf
        );
    }

    #[test]
    fn test_enhance_confidence_assignment_context() {
        let mut sin = make_sin("AWS_ACCESS_KEY", "src/main.rs", "AKIA1234567890ABCDEF");
        sin.confidence = Some(0.5);
        let lines = vec!["let key = \"AKIA1234567890ABCDEF\";"];
        enhance_confidence_with_context(&mut sin, &lines, 0);
        let conf = sin.confidence.unwrap();
        assert!(conf > 0.5, "Assignment context should boost, got {}", conf);
    }

    #[test]
    fn test_path_suggests_test_various() {
        assert!(path_suggests_test("/project/tests/scan_test.rs"));
        assert!(path_suggests_test("/project/__tests__/app.test.js"));
        assert!(path_suggests_test("spec/helper.spec.ts"));
        assert!(!path_suggests_test("src/main.rs"));
    }

    #[test]
    fn test_path_suggests_config_various() {
        assert!(path_suggests_config("app.env"));
        assert!(path_suggests_config("config.yml"));
        assert!(path_suggests_config("/project/.env.local"));
        assert!(!path_suggests_config("src/main.rs"));
    }

    #[test]
    fn test_verify_unknown_rule_returns_none() {
        let mut sin = make_sin("UNKNOWN_RULE", "src/main.rs", "some_value");
        verify(&mut sin);
        assert!(sin.verified.is_none());
    }

    #[test]
    fn test_confidence_clamp() {
        let mut sin = make_sin("AWS_ACCESS_KEY", "config.env", "AKIA1234567890ABCDEF");
        sin.verified = Some(true);
        compute_confidence(&mut sin);
        let conf = sin.confidence.unwrap();
        assert!(conf <= 1.0 && conf >= 0.0);
    }
}
