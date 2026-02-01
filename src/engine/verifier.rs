use regex::Regex;
use std::sync::LazyLock;
use std::time::Duration;

use crate::domain::Sin;

static HTTP_CLIENT: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        .user_agent(format!("velka/{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(3))
        .build()
        .expect("verifier HTTP client")
});

static GITHUB_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").expect("github token regex"));
static STRIPE_SECRET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}").expect("stripe regex"));
static SENDGRID_API_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}").expect("sendgrid regex")
});
static SLACK_WEBHOOK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+")
        .expect("slack webhook regex")
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
    let token = GITHUB_TOKEN_RE.find(snippet)?.as_str();
    let resp = HTTP_CLIENT
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .ok()?;
    Some(resp.status().is_success())
}

fn verify_stripe(snippet: &str) -> Option<bool> {
    let secret = STRIPE_SECRET_RE.find(snippet)?.as_str();
    let resp = HTTP_CLIENT
        .get("https://api.stripe.com/v1/balance")
        .basic_auth(secret, Some(""))
        .send()
        .ok()?;
    Some(resp.status().is_success())
}

fn verify_sendgrid(snippet: &str) -> Option<bool> {
    let key = SENDGRID_API_RE.find(snippet)?.as_str();
    let resp = HTTP_CLIENT
        .get("https://api.sendgrid.com/v3/user/profile")
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .ok()?;
    Some(resp.status().is_success())
}

fn verify_slack_webhook(snippet: &str) -> Option<bool> {
    let url = SLACK_WEBHOOK_RE.find(snippet)?.as_str();
    let resp = HTTP_CLIENT
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

pub fn compute_confidence(sin: &mut Sin) {
    let mut score = 0.5_f32;
    let mut factors = Vec::new();
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
