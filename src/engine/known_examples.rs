pub static KNOWN_EXAMPLE_SECRETS: &[(&str, &str)] = &[
    ("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"),
    ("AWS_SECRET_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("GOOGLE_API_KEY", "AIzaSyA1234567890abcdefghijklmnopqrstu"),
    (
        "SLACK_WEBHOOK",
        "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    ),
    (
        "SLACK_WEBHOOK",
        "xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx",
    ),
];

const EXAMPLE_SUFFIXES: &[&str] = &["EXAMPLE", "_EXAMPLE", "_TEST", "_FAKE", "_DUMMY"];
const EXAMPLE_PREFIXES: &[&str] = &["test_", "example_", "fake_", "dummy_", "sample_"];

#[must_use]
pub fn is_known_example(rule_id: &str, matched: &str) -> bool {
    let s = matched.trim();
    for (rid, literal) in KNOWN_EXAMPLE_SECRETS {
        if *rid == rule_id && s.eq_ignore_ascii_case(literal) {
            return true;
        }
    }
    if rule_id == "AWS_ACCESS_KEY" && s.ends_with("EXAMPLE") {
        return true;
    }
    let lower = s.to_lowercase();
    for suffix in EXAMPLE_SUFFIXES {
        if lower.ends_with(&suffix.to_lowercase()) {
            return true;
        }
    }
    for prefix in EXAMPLE_PREFIXES {
        if lower.starts_with(prefix) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_example_exact() {
        assert!(is_known_example("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_aws_example_suffix() {
        assert!(is_known_example(
            "AWS_ACCESS_KEY",
            "AKIAXXXXXXXXXXXXEXAMPLE"
        ));
    }

    #[test]
    fn test_aws_real_not_suppressed() {
        assert!(!is_known_example("AWS_ACCESS_KEY", "AKIA0000000000000000"));
    }

    #[test]
    fn test_prefix_test_suppressed() {
        assert!(is_known_example("GITHUB_TOKEN", "test_ghp_abc123"));
    }
}
