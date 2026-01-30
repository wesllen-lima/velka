use regex::Regex;
use std::sync::LazyLock;

use crate::domain::Sin;

static GITHUB_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").expect("github token regex"));

pub fn verify(sin: &mut Sin) {
    let verified = match sin.rule_id.as_str() {
        "GITHUB_TOKEN" => verify_github(&sin.snippet),
        _ => None,
    };
    sin.verified = verified;
}

fn verify_github(snippet: &str) -> Option<bool> {
    let token = GITHUB_TOKEN_RE.find(snippet)?.as_str();
    let client = reqwest::blocking::Client::builder()
        .user_agent("velka/1.0")
        .build()
        .ok()?;
    let resp = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("token {token}"))
        .send()
        .ok()?;
    Some(resp.status().is_success())
}
