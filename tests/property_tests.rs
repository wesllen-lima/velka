//! Property-based tests using `proptest`.
//!
//! These tests verify that validators and the scanner never panic
//! on arbitrary input, and that valid-by-construction values round-trip.

use proptest::prelude::*;
use velka::engine::compliance::{
    validate_cnpj, validate_cpf, validate_dni, validate_iban, validate_nif, validate_ssn,
};

// ---------- Never-panic properties ----------

proptest! {
    #[test]
    fn cpf_never_panics(s in "\\PC*") {
        let _ = validate_cpf(&s);
    }

    #[test]
    fn cnpj_never_panics(s in "\\PC*") {
        let _ = validate_cnpj(&s);
    }

    #[test]
    fn nif_never_panics(s in "\\PC*") {
        let _ = validate_nif(&s);
    }

    #[test]
    fn dni_never_panics(s in "\\PC*") {
        let _ = validate_dni(&s);
    }

    #[test]
    fn ssn_never_panics(s in "\\PC*") {
        let _ = validate_ssn(&s);
    }

    #[test]
    fn iban_never_panics(s in "\\PC*") {
        let _ = validate_iban(&s);
    }

    #[test]
    fn scan_str_never_panics(s in "\\PC{0,500}") {
        let _ = velka::scan_str(&s);
    }
}

// ---------- Round-trip: valid CPFs must validate ----------

/// Generate a valid CPF string (digits only, 11 chars).
fn valid_cpf_strategy() -> impl Strategy<Value = String> {
    prop::array::uniform9(0u8..10u8).prop_map(|digits| {
        let d: Vec<u8> = digits.to_vec();

        // First check digit
        let sum1: u32 = d.iter().enumerate().map(|(i, &v)| u32::from(v) * (10 - i as u32)).sum();
        let r1 = sum1 % 11;
        let d1: u8 = if r1 < 2 { 0 } else { (11 - r1) as u8 };

        // Second check digit
        let mut extended = d.clone();
        extended.push(d1);
        let sum2: u32 = extended.iter().enumerate().map(|(i, &v)| u32::from(v) * (11 - i as u32)).sum();
        let r2 = sum2 % 11;
        let d2: u8 = if r2 < 2 { 0 } else { (11 - r2) as u8 };

        let mut all = d;
        all.push(d1);
        all.push(d2);
        all.iter().map(|v| char::from(b'0' + v)).collect::<String>()
    }).prop_filter("reject all-same-digit CPFs", |cpf| {
        let bytes = cpf.as_bytes();
        !bytes.iter().all(|&b| b == bytes[0])
    })
}

proptest! {
    #[test]
    fn valid_cpf_roundtrip(cpf in valid_cpf_strategy()) {
        prop_assert!(validate_cpf(&cpf), "Generated CPF should validate: {}", cpf);
    }
}
