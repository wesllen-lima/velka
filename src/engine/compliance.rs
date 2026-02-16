use regex::Regex;
use std::sync::LazyLock;

use crate::domain::ConfidenceLevel;

// --- CPF (Brazil) ---

/// Validate a Brazilian CPF using Módulo 11.
#[must_use]
pub fn validate_cpf(cpf: &str) -> bool {
    let digits: Vec<u32> = cpf
        .chars()
        .filter(char::is_ascii_digit)
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 11 {
        return false;
    }

    // Reject all-same digits (e.g. 111.111.111-11)
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }

    // First check digit
    let sum1: u32 = digits[..9]
        .iter()
        .enumerate()
        .map(|(i, &d)| d * (10 - i as u32))
        .sum();
    let rem1 = (sum1 * 10) % 11;
    let check1 = if rem1 == 10 { 0 } else { rem1 };
    if check1 != digits[9] {
        return false;
    }

    // Second check digit
    let sum2: u32 = digits[..10]
        .iter()
        .enumerate()
        .map(|(i, &d)| d * (11 - i as u32))
        .sum();
    let rem2 = (sum2 * 10) % 11;
    let check2 = if rem2 == 10 { 0 } else { rem2 };
    check2 == digits[10]
}

// --- CNPJ (Brazil) ---

/// Validate a Brazilian CNPJ using Módulo 11.
#[must_use]
pub fn validate_cnpj(cnpj: &str) -> bool {
    let digits: Vec<u32> = cnpj
        .chars()
        .filter(char::is_ascii_digit)
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 14 {
        return false;
    }

    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }

    let weights1: &[u32] = &[5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum1: u32 = digits[..12]
        .iter()
        .zip(weights1.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let rem1 = sum1 % 11;
    let check1 = if rem1 < 2 { 0 } else { 11 - rem1 };
    if check1 != digits[12] {
        return false;
    }

    let weights2: &[u32] = &[6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum2: u32 = digits[..13]
        .iter()
        .zip(weights2.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let rem2 = sum2 % 11;
    let check2 = if rem2 < 2 { 0 } else { 11 - rem2 };
    check2 == digits[13]
}

// --- DSN Parser ---

static DSN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|mariadb|jdbc:[a-z:]+)://[^:]+:([^@]+)@")
        .expect("DSN regex")
});

static PLACEHOLDER_VALUES: &[&str] = &[
    "password",
    "changeme",
    "example",
    "secret",
    "pass",
    "test",
    "placeholder",
    "xxx",
    "your_password",
    "your-password",
    "your_pass",
];

/// Extract a password from a DSN/connection string.
/// Returns `None` if no password found or it's a known placeholder.
#[must_use]
pub fn extract_dsn_password(dsn: &str) -> Option<String> {
    let caps = DSN_RE.captures(dsn)?;
    let password = caps.get(1)?.as_str().to_string();

    let lower = password.to_lowercase();
    if PLACEHOLDER_VALUES.iter().any(|&p| lower == p) {
        return None;
    }

    Some(password)
}

/// Structural validation for CPF rule
#[must_use]
pub fn validate_cpf_confidence(snippet: &str) -> ConfidenceLevel {
    static CPF_EXTRACT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b").expect("CPF extract regex")
    });

    let Some(mat) = CPF_EXTRACT_RE.find(snippet) else {
        return ConfidenceLevel::Suspicious;
    };

    if validate_cpf(mat.as_str()) {
        ConfidenceLevel::Critical
    } else {
        ConfidenceLevel::Info
    }
}

/// Structural validation for CNPJ rule
#[must_use]
pub fn validate_cnpj_confidence(snippet: &str) -> ConfidenceLevel {
    static CNPJ_EXTRACT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b").expect("CNPJ extract regex")
    });

    let Some(mat) = CNPJ_EXTRACT_RE.find(snippet) else {
        return ConfidenceLevel::Suspicious;
    };

    if validate_cnpj(mat.as_str()) {
        ConfidenceLevel::Critical
    } else {
        ConfidenceLevel::Info
    }
}

/// Structural validation for `DSN_CREDENTIALS` rule
#[must_use]
pub fn validate_dsn_confidence(snippet: &str) -> ConfidenceLevel {
    if extract_dsn_password(snippet).is_some() {
        ConfidenceLevel::Critical
    } else {
        ConfidenceLevel::Suspicious
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- CPF ---

    #[test]
    fn test_cpf_valid_formatted() {
        assert!(validate_cpf("529.982.247-25"));
    }

    #[test]
    fn test_cpf_valid_unformatted() {
        assert!(validate_cpf("52998224725"));
    }

    #[test]
    fn test_cpf_invalid_check_digit() {
        assert!(!validate_cpf("529.982.247-26"));
    }

    #[test]
    fn test_cpf_all_same_digits() {
        assert!(!validate_cpf("111.111.111-11"));
        assert!(!validate_cpf("000.000.000-00"));
    }

    #[test]
    fn test_cpf_wrong_length() {
        assert!(!validate_cpf("123.456.789"));
        assert!(!validate_cpf("123.456.789-012"));
    }

    // --- CNPJ ---

    #[test]
    fn test_cnpj_valid_formatted() {
        assert!(validate_cnpj("11.222.333/0001-81"));
    }

    #[test]
    fn test_cnpj_valid_unformatted() {
        assert!(validate_cnpj("11222333000181"));
    }

    #[test]
    fn test_cnpj_invalid_check_digit() {
        assert!(!validate_cnpj("11.222.333/0001-82"));
    }

    #[test]
    fn test_cnpj_all_same_digits() {
        assert!(!validate_cnpj("11.111.111/1111-11"));
    }

    #[test]
    fn test_cnpj_wrong_length() {
        assert!(!validate_cnpj("11222333000"));
    }

    // --- DSN ---

    #[test]
    fn test_dsn_postgresql() {
        let dsn = "postgresql://admin:s3cr3tPass@db.prod.example.com:5432/mydb";
        assert_eq!(extract_dsn_password(dsn), Some("s3cr3tPass".to_string()));
    }

    #[test]
    fn test_dsn_mongodb_srv() {
        let dsn = "mongodb+srv://user:hunter2@cluster0.mongodb.net/db";
        assert_eq!(extract_dsn_password(dsn), Some("hunter2".to_string()));
    }

    #[test]
    fn test_dsn_redis() {
        let dsn = "redis://default:mypass@redis.example.com:6379";
        assert_eq!(extract_dsn_password(dsn), Some("mypass".to_string()));
    }

    #[test]
    fn test_dsn_placeholder_ignored() {
        let dsn = "postgresql://admin:password@localhost/db";
        assert_eq!(extract_dsn_password(dsn), None);
    }

    #[test]
    fn test_dsn_changeme_ignored() {
        let dsn = "mysql://root:changeme@localhost/db";
        assert_eq!(extract_dsn_password(dsn), None);
    }

    #[test]
    fn test_dsn_no_password() {
        let dsn = "postgresql://admin@localhost/db";
        assert_eq!(extract_dsn_password(dsn), None);
    }

    #[test]
    fn test_dsn_jdbc() {
        let dsn = "jdbc:postgresql://user:real_pass@db:5432/mydb";
        assert_eq!(extract_dsn_password(dsn), Some("real_pass".to_string()));
    }

    #[test]
    fn test_dsn_mssql() {
        let dsn = "mssql://sa:MyS3cur3Pass@sqlserver.prod.com:1433/master";
        assert_eq!(extract_dsn_password(dsn), Some("MyS3cur3Pass".to_string()));
    }

    #[test]
    fn test_dsn_stripe_in_postgresql() {
        let fake_key = format!("sk_live_{}", "abc123def456ghi789jkl012");
        let dsn = format!("postgresql://admin:{fake_key}@db:5432/app");
        assert_eq!(extract_dsn_password(&dsn), Some(fake_key));
    }
}
