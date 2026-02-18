//! Regression tests for known false-positive scenarios.
//!
//! Each test verifies that Velka does NOT flag benign content that once
//! triggered a rule. Uses `velka::scan_str()` as the single entry-point.

/// Helper: asserts that `scan_str` returns zero findings for the given input.
fn assert_no_findings(input: &str) {
    let findings = velka::scan_str(input).expect("scan_str should not fail");
    assert!(
        findings.is_empty(),
        "Expected no findings for input, but got {}: {:?}",
        findings.len(),
        findings.iter().map(|s| &s.rule_id).collect::<Vec<_>>()
    );
}

// ---------- Regex patterns in source code ----------

#[test]
fn regex_pattern_not_flagged() {
    // A regex literal that happens to match the AWS key pattern
    assert_no_findings(r#"let re = Regex::new(r"(AKIA|ASIA)[A-Z0-9]{16}").unwrap();"#);
}

#[test]
fn regex_pattern_hex_not_flagged() {
    assert_no_findings(r#"let re = Regex::new(r"[0-9a-fA-F]{40}").unwrap();"#);
}

// ---------- Documentation example keys ----------

#[test]
fn aws_example_key_not_flagged() {
    assert_no_findings(r#"let key = "AKIAIOSFODNN7EXAMPLE";"#);
}

// ---------- Hardcoded "password" in example variable names ----------

#[test]
fn example_password_variable_not_flagged() {
    assert_no_findings(r#"let example_password = "changeme";"#);
}

#[test]
fn test_password_variable_not_flagged() {
    assert_no_findings(r#"let test_password = "hunter2";"#);
}

// ---------- Generic base64 padding ----------

#[test]
fn base64_padding_not_flagged() {
    // Short base64 strings that are just padding noise
    assert_no_findings("data = \"AAAAAAAAAA==\"");
}

#[test]
fn generic_base64_config_not_flagged() {
    // A base64-encoded value that is not a secret
    assert_no_findings("icon = \"aWNvbg==\""); // "icon" in base64
}

// ---------- Public URLs with long tokens ----------

#[test]
fn public_url_not_flagged() {
    assert_no_findings(
        "https://cdn.example.com/assets/bundle-abc123def456ghi789jkl012mno345pqr678.min.js",
    );
}

// ---------- Clean code should be clean ----------

#[test]
fn plain_rust_code_not_flagged() {
    assert_no_findings(
        r#"
fn main() {
    let x = 42;
    println!("Hello, world! {}", x);
}
"#,
    );
}

#[test]
fn plain_python_code_not_flagged() {
    assert_no_findings(
        r#"
def hello():
    name = "world"
    print(f"Hello, {name}!")
"#,
    );
}
