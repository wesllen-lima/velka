use regex::Regex;
use std::sync::LazyLock;

use crate::domain::ConfidenceLevel;
use crate::engine::compliance;

static AWS_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(AKIA|ASIA)[A-Z0-9]{16}").expect("AWS key regex"));

static STRIPE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}").expect("Stripe key regex")
});

/// Extract an AWS key from a snippet and validate its structure.
/// Format: AKIA/ASIA + 16 uppercase alphanumeric chars (total 20).
#[must_use]
pub fn validate_aws_access_key(snippet: &str) -> ConfidenceLevel {
    let Some(mat) = AWS_KEY_RE.find(snippet) else {
        return ConfidenceLevel::Suspicious;
    };
    let key = mat.as_str();

    if key.len() != 20 {
        return ConfidenceLevel::Suspicious;
    }

    let suffix = &key[4..];

    // Checksum heuristic: reject if all chars are identical (dummy key)
    let bytes = suffix.as_bytes();
    if bytes.iter().all(|&b| b == bytes[0]) {
        return ConfidenceLevel::Suspicious;
    }

    ConfidenceLevel::Critical
}

/// Extract a Stripe key from a snippet and validate its structure.
/// `sk_live_` prefix → Critical (production key).
/// `sk_test_` prefix → always Suspicious (test key, never Info — Zero Leak Policy).
/// `rk_live_` / `rk_test_` (restricted keys) follow same logic.
#[must_use]
pub fn validate_stripe_key(snippet: &str) -> ConfidenceLevel {
    let Some(mat) = STRIPE_KEY_RE.find(snippet) else {
        return ConfidenceLevel::Suspicious;
    };
    let key = mat.as_str();

    if key.starts_with("sk_live_") || key.starts_with("rk_live_") {
        if key.len() >= 32 {
            return ConfidenceLevel::Critical;
        }
        return ConfidenceLevel::Suspicious;
    }

    if key.starts_with("sk_test_") || key.starts_with("rk_test_") {
        return ConfidenceLevel::Suspicious;
    }

    ConfidenceLevel::Suspicious
}

/// Apply structural validation for a given rule.
/// The snippet is the full line — validators extract the key internally.
/// Zero Leak Policy: if a regex matched, the minimum is Suspicious.
#[must_use]
pub fn validate_for_rule(snippet: &str, rule_id: &str) -> Option<ConfidenceLevel> {
    match rule_id {
        "AWS_ACCESS_KEY" => Some(validate_aws_access_key(snippet)),
        "STRIPE_SECRET" => Some(validate_stripe_key(snippet)),
        "BRAZILIAN_CPF" => Some(compliance::validate_cpf_confidence(snippet)),
        "BRAZILIAN_CNPJ" => Some(compliance::validate_cnpj_confidence(snippet)),
        "DSN_CREDENTIALS" => Some(compliance::validate_dsn_confidence(snippet)),
        "NIF_PT" => Some(compliance::validate_nif_confidence(snippet)),
        "DNI_ES" => Some(compliance::validate_dni_confidence(snippet)),
        "SSN_US" => Some(compliance::validate_ssn_confidence(snippet)),
        "IBAN" => Some(compliance::validate_iban_confidence(snippet)),
        _ => None,
    }
}

/// Enforce Zero Leak Policy: a regex-matched finding must be at minimum Suspicious.
/// This guarantees that no true positive can slip through as Info.
#[must_use]
pub fn enforce_zero_leak_floor(level: ConfidenceLevel) -> ConfidenceLevel {
    level.max(ConfidenceLevel::Suspicious)
}

/// Build a test Stripe key at runtime to avoid triggering GitHub Push Protection.
#[cfg(test)]
fn fake_stripe_key(prefix: &str) -> String {
    format!("{prefix}abcdefghijklmnopqrstuvwx1234")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- AWS Access Key ---

    #[test]
    fn test_aws_valid_production_key() {
        assert_eq!(
            validate_aws_access_key("AKIA1234567890ABCDEF"),
            ConfidenceLevel::Critical
        );
    }

    #[test]
    fn test_aws_asia_prefix() {
        assert_eq!(
            validate_aws_access_key("ASIA1234567890ABCDEF"),
            ConfidenceLevel::Critical
        );
    }

    #[test]
    fn test_aws_wrong_length() {
        assert_eq!(
            validate_aws_access_key("AKIA12345"),
            ConfidenceLevel::Suspicious
        );
    }

    #[test]
    fn test_aws_lowercase_chars() {
        assert_eq!(
            validate_aws_access_key("AKIAabcdefghijklmnop"),
            ConfidenceLevel::Suspicious
        );
    }

    #[test]
    fn test_aws_all_identical_suffix() {
        assert_eq!(
            validate_aws_access_key("AKIAAAAAAAAAAAAAAAAAAA"[..20].to_string().as_str()),
            ConfidenceLevel::Suspicious
        );
    }

    #[test]
    fn test_aws_bad_prefix() {
        assert_eq!(
            validate_aws_access_key("XKIA1234567890ABCDEF"),
            ConfidenceLevel::Suspicious
        );
    }

    // --- Stripe Key ---

    #[test]
    fn test_stripe_live_key_critical() {
        assert_eq!(
            validate_stripe_key(&fake_stripe_key("sk_live_")),
            ConfidenceLevel::Critical
        );
    }

    #[test]
    fn test_stripe_test_key_suspicious() {
        assert_eq!(
            validate_stripe_key(&fake_stripe_key("sk_test_")),
            ConfidenceLevel::Suspicious
        );
    }

    #[test]
    fn test_stripe_no_match_in_snippet() {
        // If the regex doesn't find a valid Stripe key, returns Suspicious
        assert_eq!(
            validate_stripe_key("some random text with no stripe key"),
            ConfidenceLevel::Suspicious
        );
    }

    #[test]
    fn test_stripe_restricted_live() {
        assert_eq!(
            validate_stripe_key(&fake_stripe_key("rk_live_")),
            ConfidenceLevel::Critical
        );
    }

    #[test]
    fn test_stripe_restricted_test() {
        assert_eq!(
            validate_stripe_key(&fake_stripe_key("rk_test_")),
            ConfidenceLevel::Suspicious
        );
    }

    // --- validate_for_rule ---

    #[test]
    fn test_validate_for_rule_aws() {
        assert_eq!(
            validate_for_rule("AKIA1234567890ABCDEF", "AWS_ACCESS_KEY"),
            Some(ConfidenceLevel::Critical)
        );
    }

    #[test]
    fn test_validate_for_rule_stripe() {
        assert_eq!(
            validate_for_rule(&fake_stripe_key("sk_test_"), "STRIPE_SECRET"),
            Some(ConfidenceLevel::Suspicious)
        );
    }

    #[test]
    fn test_validate_for_rule_unknown() {
        assert_eq!(validate_for_rule("anything", "UNKNOWN_RULE"), None);
    }

    // --- Zero Leak Policy ---

    #[test]
    fn test_zero_leak_floor_promotes_info() {
        assert_eq!(
            enforce_zero_leak_floor(ConfidenceLevel::Info),
            ConfidenceLevel::Suspicious
        );
    }

    #[test]
    fn test_zero_leak_floor_keeps_suspicious() {
        assert_eq!(
            enforce_zero_leak_floor(ConfidenceLevel::Suspicious),
            ConfidenceLevel::Suspicious
        );
    }

    #[test]
    fn test_zero_leak_floor_keeps_critical() {
        assert_eq!(
            enforce_zero_leak_floor(ConfidenceLevel::Critical),
            ConfidenceLevel::Critical
        );
    }

    // --- Snippet extraction (full line) ---

    #[test]
    fn test_aws_key_in_full_line() {
        assert_eq!(
            validate_aws_access_key(r"AWS_KEY=AKIA1234567890ABCDEF"),
            ConfidenceLevel::Critical
        );
    }

    #[test]
    fn test_stripe_key_in_full_line() {
        let line = format!(r#"STRIPE_KEY="{}""#, fake_stripe_key("sk_live_"));
        assert_eq!(validate_stripe_key(&line), ConfidenceLevel::Critical);
    }

    #[test]
    fn test_stripe_test_key_in_full_line() {
        let line = format!(r#"STRIPE_KEY="{}""#, fake_stripe_key("sk_test_"));
        assert_eq!(validate_stripe_key(&line), ConfidenceLevel::Suspicious);
    }

    // --- ConfidenceLevel ordering ---

    #[test]
    fn test_confidence_level_ordering() {
        assert!(ConfidenceLevel::Info < ConfidenceLevel::Suspicious);
        assert!(ConfidenceLevel::Suspicious < ConfidenceLevel::Critical);
    }

    #[test]
    fn test_confidence_level_from_score() {
        assert_eq!(ConfidenceLevel::from_score(0.1), ConfidenceLevel::Info);
        assert_eq!(ConfidenceLevel::from_score(0.39), ConfidenceLevel::Info);
        assert_eq!(
            ConfidenceLevel::from_score(0.4),
            ConfidenceLevel::Suspicious
        );
        assert_eq!(
            ConfidenceLevel::from_score(0.74),
            ConfidenceLevel::Suspicious
        );
        assert_eq!(ConfidenceLevel::from_score(0.75), ConfidenceLevel::Critical);
        assert_eq!(ConfidenceLevel::from_score(1.0), ConfidenceLevel::Critical);
    }
}
