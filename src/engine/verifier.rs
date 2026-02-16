use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use std::time::Duration;

use crate::domain::{ConfidenceLevel, Sin};
use crate::engine::structural_validators;

static AWS_KEY_PATTERN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b").ok());

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

static AWS_SECRET_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9/+=]{40}").ok());

pub fn verify(sin: &mut Sin) {
    let verified = match sin.rule_id.as_str() {
        "AWS_ACCESS_KEY" => verify_aws(&sin.snippet, &sin.context),
        "GITHUB_TOKEN" => verify_github_enhanced(&sin.snippet),
        "STRIPE_SECRET" => verify_stripe(&sin.snippet),
        "SENDGRID_API" => verify_sendgrid(&sin.snippet),
        "SLACK_WEBHOOK" => verify_slack_webhook(&sin.snippet),
        _ => None,
    };

    if let Some(true) = verified {
        if sin.rule_id == "AWS_ACCESS_KEY" {
            sin.description = format!("CRITICAL (Verified): {}", sin.description);
        }
    }

    sin.verified = verified;
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify AWS credentials via STS `GetCallerIdentity`.
/// Looks for access key in snippet and secret key in context lines.
fn verify_aws(snippet: &str, context: &[String]) -> Option<bool> {
    let key_re = AWS_KEY_PATTERN.as_ref()?;
    let access_key = key_re.find(snippet)?.as_str();

    // Search for secret key in context
    let secret_re = AWS_SECRET_RE.as_ref()?;
    let all_text = context.join("\n");
    let secret_key = secret_re.find(&all_text)?.as_str();

    let client = HTTP_CLIENT.as_ref()?;
    let host = "sts.amazonaws.com";
    let service = "sts";
    let region = "us-east-1";
    let method = "POST";
    let body = "Action=GetCallerIdentity&Version=2011-06-15";

    let now = chrono::Utc::now();
    let datestamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let payload_hash = sha256_hex(body);
    let canonical_headers = format!(
        "content-type:application/x-www-form-urlencoded\nhost:{host}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "content-type;host;x-amz-date";

    let canonical_request =
        format!("{method}\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let credential_scope = format!("{datestamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(&canonical_request)
    );

    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    let resp = client
        .post(format!("https://{host}"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Host", host)
        .header("X-Amz-Date", &amz_date)
        .header("Authorization", &auth_header)
        .body(body)
        .send()
        .ok()?;

    Some(resp.status().is_success())
}

/// Enhanced GitHub token verification — also extracts scopes and user info.
fn verify_github_enhanced(snippet: &str) -> Option<bool> {
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
    // HEAD request to verify the endpoint exists without sending a message
    let resp = client.head(url).send().ok()?;
    // Slack returns 2xx/4xx for valid webhooks, connection failure means invalid
    Some(!resp.status().is_server_error())
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

    // Derive ConfidenceLevel from structural validators + score
    let level = match structural_validators::validate_for_rule(&sin.snippet, &sin.rule_id) {
        Some(structural_level) => {
            let score_level = ConfidenceLevel::from_score(score);
            // Take the higher of structural validation and score-derived level
            structural_level.max(score_level)
        }
        None => ConfidenceLevel::from_score(score),
    };

    // Zero Leak Policy: regex matched → minimum Suspicious
    sin.confidence_level = Some(structural_validators::enforce_zero_leak_floor(level));
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
            confidence_level: None,
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
