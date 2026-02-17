//! Compliance validators for PII document numbers.
//!
//! Each validator implements the official check-digit algorithm for its
//! document type: Brazilian CPF/CNPJ, Portuguese NIF, Spanish DNI,
//! US SSN (structural), and IBAN (MOD-97).
//!
//! All public functions return `bool` — `true` when the input passes
//! both structural and mathematical validation.

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

// --- NIF Portugal ---

/// Validate a Portuguese NIF (Número de Identificação Fiscal) using Módulo 11.
#[must_use]
pub fn validate_nif(nif: &str) -> bool {
    let digits: Vec<u32> = nif
        .chars()
        .filter(char::is_ascii_digit)
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 9 {
        return false;
    }

    // First digit must be 1-9
    if digits[0] == 0 {
        return false;
    }

    let weights: &[u32] = &[9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits[..8]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let rem = sum % 11;
    let check = if rem < 2 { 0 } else { 11 - rem };
    check == digits[8]
}

/// Structural validation for NIF rule.
#[must_use]
pub fn validate_nif_confidence(snippet: &str) -> ConfidenceLevel {
    static NIF_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b[1-9]\d{8}\b").expect("NIF regex"));

    let Some(mat) = NIF_RE.find(snippet) else {
        return ConfidenceLevel::Suspicious;
    };

    if validate_nif(mat.as_str()) {
        ConfidenceLevel::Critical
    } else {
        ConfidenceLevel::Info
    }
}

// --- DNI Spain ---

/// Validate a Spanish DNI (Documento Nacional de Identidad).
/// Format: 8 digits + 1 control letter.
#[must_use]
pub fn validate_dni(dni: &str) -> bool {
    const TABLE: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";

    let clean: String = dni
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();

    if !clean.is_ascii() || clean.len() != 9 {
        return false;
    }

    let number_part = &clean[..8];
    let letter = clean.chars().last().unwrap_or(' ');

    let Ok(number) = number_part.parse::<u32>() else {
        return false;
    };

    let expected = TABLE[(number % 23) as usize] as char;

    letter.to_ascii_uppercase() == expected
}

/// Structural validation for DNI rule.
#[must_use]
pub fn validate_dni_confidence(snippet: &str) -> ConfidenceLevel {
    static DNI_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b\d{8}[A-Za-z]\b").expect("DNI regex"));

    let Some(mat) = DNI_RE.find(snippet) else {
        return ConfidenceLevel::Suspicious;
    };

    if validate_dni(mat.as_str()) {
        ConfidenceLevel::Critical
    } else {
        ConfidenceLevel::Info
    }
}

// --- SSN USA ---

/// Validate a US Social Security Number (structural only, no check digit).
/// Format: AAA-BB-CCCC where AAA != 000/666/900-999, BB != 00, CCCC != 0000.
#[must_use]
pub fn validate_ssn(ssn: &str) -> bool {
    let digits: Vec<u32> = ssn
        .chars()
        .filter(char::is_ascii_digit)
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 9 {
        return false;
    }

    let area = digits[0] * 100 + digits[1] * 10 + digits[2];
    let group = digits[3] * 10 + digits[4];
    let serial = digits[5] * 1000 + digits[6] * 100 + digits[7] * 10 + digits[8];

    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    if group == 0 {
        return false;
    }
    if serial == 0 {
        return false;
    }

    true
}

/// Structural validation for SSN rule.
#[must_use]
pub fn validate_ssn_confidence(snippet: &str) -> ConfidenceLevel {
    static SSN_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("SSN regex"));

    let Some(mat) = SSN_RE.find(snippet) else {
        return ConfidenceLevel::Suspicious;
    };

    if validate_ssn(mat.as_str()) {
        ConfidenceLevel::Critical
    } else {
        ConfidenceLevel::Info
    }
}

// --- IBAN ---

/// Validate an IBAN using MOD-97 algorithm (ISO 13616).
#[must_use]
pub fn validate_iban(iban: &str) -> bool {
    let clean: String = iban
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();

    if !clean.is_ascii() || clean.len() < 5 || clean.len() > 34 {
        return false;
    }

    // First 2 chars must be letters (country code)
    if !clean[..2].chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }

    // Chars 3-4 must be digits (check digits)
    if !clean[2..4].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Remaining must be alphanumeric
    if !clean[4..].chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }

    // MOD-97 check: move first 4 chars to end, convert letters to numbers
    let rearranged = format!("{}{}", &clean[4..], &clean[..4]);
    let numeric: String = rearranged
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                c.to_string()
            } else {
                (c as u32 - u32::from(b'A') + 10).to_string()
            }
        })
        .collect();

    // Calculate mod 97 using chunks to avoid overflow
    let mut remainder: u64 = 0;
    for chunk in numeric.as_bytes().chunks(9) {
        let s: String = std::str::from_utf8(chunk).unwrap_or("0").to_string();
        let combined = format!("{remainder}{s}");
        remainder = combined.parse::<u64>().unwrap_or(0) % 97;
    }

    remainder == 1
}

/// Structural validation for IBAN rule.
#[must_use]
pub fn validate_iban_confidence(snippet: &str) -> ConfidenceLevel {
    static IBAN_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b").expect("IBAN regex"));

    let Some(mat) = IBAN_RE.find(snippet) else {
        return ConfidenceLevel::Suspicious;
    };

    if validate_iban(mat.as_str()) {
        ConfidenceLevel::Critical
    } else {
        ConfidenceLevel::Info
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

    // --- NIF Portugal ---

    #[test]
    fn test_nif_valid() {
        assert!(validate_nif("123456789"));
    }

    #[test]
    fn test_nif_invalid_check_digit() {
        assert!(!validate_nif("123456780"));
    }

    #[test]
    fn test_nif_wrong_length() {
        assert!(!validate_nif("12345"));
    }

    #[test]
    fn test_nif_starts_with_zero() {
        assert!(!validate_nif("012345678"));
    }

    // --- DNI Spain ---

    #[test]
    fn test_dni_valid() {
        // 12345678Z is valid: 12345678 % 23 = 14 → TABLE[14] = 'Z'
        assert!(validate_dni("12345678Z"));
    }

    #[test]
    fn test_dni_invalid_letter() {
        assert!(!validate_dni("12345678A"));
    }

    #[test]
    fn test_dni_wrong_length() {
        assert!(!validate_dni("1234567Z"));
    }

    // --- SSN USA ---

    #[test]
    fn test_ssn_valid() {
        assert!(validate_ssn("123-45-6789"));
    }

    #[test]
    fn test_ssn_area_zero() {
        assert!(!validate_ssn("000-45-6789"));
    }

    #[test]
    fn test_ssn_area_666() {
        assert!(!validate_ssn("666-45-6789"));
    }

    #[test]
    fn test_ssn_area_900_plus() {
        assert!(!validate_ssn("900-45-6789"));
    }

    #[test]
    fn test_ssn_group_zero() {
        assert!(!validate_ssn("123-00-6789"));
    }

    #[test]
    fn test_ssn_serial_zero() {
        assert!(!validate_ssn("123-45-0000"));
    }

    // --- IBAN ---

    #[test]
    fn test_iban_valid_gb() {
        assert!(validate_iban("GB29NWBK60161331926819"));
    }

    #[test]
    fn test_iban_valid_de() {
        assert!(validate_iban("DE89370400440532013000"));
    }

    #[test]
    fn test_iban_invalid_check() {
        assert!(!validate_iban("GB29NWBK60161331926818"));
    }

    #[test]
    fn test_iban_too_short() {
        assert!(!validate_iban("GB29"));
    }

    #[test]
    fn test_dsn_stripe_in_postgresql() {
        let fake_key = format!("sk_live_{}", "abc123def456ghi789jkl012");
        let dsn = format!("postgresql://admin:{fake_key}@db:5432/app");
        assert_eq!(extract_dsn_password(&dsn), Some(fake_key));
    }
}
