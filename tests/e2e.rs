//! End-to-end test: Detection -> ML Classification -> LSP Diagnostic -> Quarantine

use std::fs;

use crossbeam_channel::unbounded;
use tempfile::TempDir;

use velka::engine::ml_classifier::classify_default;
use velka::engine::quarantine;
use velka::engine::structural_validators;
use velka::engine::{scan_content, scan_single_file};
use velka::{ConfidenceLevel, VelkaConfig};

/// Full pipeline: detect secret -> classify with ML -> produce LSP-compatible diagnostic -> quarantine file
#[test]
fn e2e_detect_classify_quarantine_pipeline() {
    let temp = TempDir::new().unwrap();
    let secret_file = temp.path().join("config.env");
    let secret_content = r"AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
DB_HOST=localhost
DB_PORT=5432
GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890
CLEAN_VAR=hello_world
";
    fs::write(&secret_file, secret_content).unwrap();

    // --- STEP 1: Detection ---
    let config = VelkaConfig::default();
    let (sender, receiver) = unbounded();
    scan_single_file(&secret_file, &config, &sender, None).unwrap();
    drop(sender);
    let sins: Vec<_> = receiver.iter().collect();

    assert!(
        sins.len() >= 2,
        "Expected at least 2 secrets, found {}",
        sins.len()
    );

    let aws_sin = sins.iter().find(|s| s.rule_id == "AWS_ACCESS_KEY");
    let gh_sin = sins.iter().find(|s| s.rule_id == "GITHUB_TOKEN");
    assert!(aws_sin.is_some(), "AWS key not detected");
    assert!(gh_sin.is_some(), "GitHub token not detected");

    // --- STEP 2: ML Classification ---
    let aws_classification = classify_default("AKIA1234567890ABCDEF", "AWS_ACCESS_KEY");
    assert!(
        aws_classification.is_secret,
        "ML classifier should mark AWS key as secret, score: {}",
        aws_classification.score
    );
    assert!(
        aws_classification.score > 0.6,
        "AWS key confidence too low: {}",
        aws_classification.score
    );

    let gh_classification =
        classify_default("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", "GITHUB_TOKEN");
    assert!(
        gh_classification.is_secret,
        "ML classifier should mark GitHub token as secret"
    );

    // Verify clean string is NOT classified as secret
    let clean_classification = classify_default("hello_world", "GENERIC_SECRET");
    assert!(
        !clean_classification.is_secret,
        "Clean string should not be classified as secret, score: {}",
        clean_classification.score
    );

    // --- STEP 3: LSP Diagnostic Simulation ---
    // Verify the sin has the correct fields for LSP diagnostic generation
    let aws = aws_sin.unwrap();
    assert_eq!(aws.rule_id, "AWS_ACCESS_KEY");
    assert!(aws.line_number > 0, "Line number must be positive");
    assert!(
        !aws.description.is_empty(),
        "Description required for LSP diagnostic"
    );
    // Severity mapping: Mortal -> DiagnosticSeverity::ERROR
    assert_eq!(aws.severity, velka::Severity::Mortal);

    // --- STEP 4: Quarantine ---
    let candidates = quarantine::filter_quarantine_candidates(&sins);
    assert!(
        !candidates.is_empty(),
        "Mortal sins should be quarantine candidates"
    );

    let entry = quarantine::quarantine_file(temp.path(), &secret_file).unwrap();
    assert!(
        !secret_file.exists(),
        "Original file should be removed after quarantine"
    );
    assert!(
        entry.quarantine_path.exists(),
        "Quarantined file should exist"
    );
    assert!(!entry.sha256.is_empty(), "SHA256 hash should be populated");

    // Verify quarantine listing
    let quarantined = quarantine::list_quarantined(temp.path()).unwrap();
    assert!(
        !quarantined.is_empty(),
        "Quarantine list should contain the file"
    );

    // --- STEP 5: Restore ---
    let flat_name = entry
        .quarantine_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let restored = quarantine::restore_file(temp.path(), &flat_name).unwrap();
    assert!(restored.exists(), "File should be restored");
    let restored_content = fs::read_to_string(&restored).unwrap();
    assert_eq!(
        restored_content, secret_content,
        "Content should be preserved after restore"
    );
}

/// Test: `scan_content` detects multiple secret types in a single content block
#[test]
fn e2e_multi_secret_detection() {
    let config = VelkaConfig::default();
    let fake_stripe = format!("sk_live_{}", "a".repeat(24));
    let content = format!(
        r#"
const AWS_KEY = "AKIA9876543210FEDCBA";
const GH_TOKEN = "ghp_xYzAbCdEfGhIjKlMnOpQrStUvWxYz12345678";
const STRIPE = "{fake_stripe}";
const GOOGLE = "AIzaSyA1234567890abcdefghijklmnopqrstu";
"#
    );

    let sins = scan_content(&content, &config).unwrap();
    let rule_ids: Vec<&str> = sins.iter().map(|s| s.rule_id.as_str()).collect();

    assert!(
        rule_ids.contains(&"AWS_ACCESS_KEY"),
        "AWS key not found in {rule_ids:?}"
    );
    assert!(
        rule_ids.contains(&"GITHUB_TOKEN"),
        "GitHub token not found in {rule_ids:?}"
    );
    assert!(
        rule_ids.contains(&"STRIPE_SECRET"),
        "Stripe key not found in {rule_ids:?}"
    );
}

/// Test: ML classifier returns factors for each scoring dimension
#[test]
fn e2e_ml_classifier_factors() {
    let result = classify_default("AKIA1234567890ABCDEF", "AWS_ACCESS_KEY");
    let factor_names: Vec<&str> = result.factors.iter().map(|(name, _)| *name).collect();

    assert!(factor_names.contains(&"entropy"), "Missing entropy factor");
    assert!(
        factor_names.contains(&"char_frequency"),
        "Missing char_frequency factor"
    );
    assert!(
        factor_names.contains(&"structural"),
        "Missing structural factor"
    );
    assert!(factor_names.contains(&"length"), "Missing length factor");

    // Structural score for valid AWS key should be 1.0
    let structural = result
        .factors
        .iter()
        .find(|(name, _)| *name == "structural")
        .unwrap();
    assert!(
        (structural.1 - 1.0).abs() < f32::EPSILON,
        "Structural score for valid AWS key should be 1.0, got {}",
        structural.1
    );
}

/// Test: velka:ignore annotation prevents detection
#[test]
fn e2e_ignore_annotation() {
    let config = VelkaConfig::default();
    let content = r#"let key = "AKIA0000000000000000"; // velka:ignore"#;
    let sins = scan_content(content, &config).unwrap();
    assert!(sins.is_empty(), "velka:ignore should suppress detection");
}

/// Test: velka:ignore-start/end block suppression
#[test]
fn e2e_ignore_block() {
    let config = VelkaConfig::default();
    let content = r#"
// velka:ignore-start
let key1 = "AKIA1111111111111111";
let key2 = "AKIA2222222222222222";
// velka:ignore-end
let key3 = "AKIA3333333333333333";
"#;
    let sins = scan_content(content, &config).unwrap();
    // Only key3 should be detected (outside ignore block)
    assert_eq!(
        sins.len(),
        1,
        "Only 1 sin expected outside ignore block, found {}",
        sins.len()
    );
    assert!(sins[0].snippet.contains("AKIA3333333333333333"));
}

/// Test: Honeytoken detection does not trigger false positives
#[test]
fn e2e_honeytoken_skipped() {
    let config = VelkaConfig::default();
    // Content with honeytoken marker should be skipped
    let content = r#"let trap = "AKIA0000000000000000"; // velka:honeytoken"#;
    let sins = scan_content(content, &config).unwrap();
    assert!(sins.is_empty(), "Honeytoken-marked lines should be skipped");
}

/// Test: Full pipeline from regex match → structural validation → `ConfidenceLevel` assignment
#[test]
fn e2e_confidence_scoring_pipeline_aws() {
    let temp = TempDir::new().unwrap();
    let secret_file = temp.path().join("prod.env");
    fs::write(&secret_file, "AWS_KEY=AKIA1234567890ABCDEF\n").unwrap();

    let config = VelkaConfig::default();
    let (sender, receiver) = unbounded();
    scan_single_file(&secret_file, &config, &sender, None).unwrap();
    drop(sender);
    let sins: Vec<_> = receiver.iter().collect();

    let aws = sins.iter().find(|s| s.rule_id == "AWS_ACCESS_KEY").unwrap();

    // Pipeline must assign confidence_level
    assert!(
        aws.confidence_level.is_some(),
        "confidence_level must be set after compute_confidence"
    );

    // Valid AKIA key in a .env file → Critical
    assert_eq!(
        aws.confidence_level.unwrap(),
        ConfidenceLevel::Critical,
        "Valid AWS key in config file must be Critical"
    );

    // Numeric confidence must also be populated
    assert!(aws.confidence.is_some());
    assert!(aws.confidence.unwrap() >= 0.75);
}

/// Test: Stripe test key gets Suspicious (never Info — Zero Leak Policy)
#[test]
fn e2e_confidence_scoring_stripe_test_key() {
    let config = VelkaConfig::default();
    let fake_test_stripe = format!("sk_test_{}", "a".repeat(24));
    let content = format!(r#"STRIPE_KEY="{fake_test_stripe}""#);

    let sins = scan_content(&content, &config).unwrap();
    let stripe = sins.iter().find(|s| s.rule_id == "STRIPE_SECRET");
    assert!(stripe.is_some(), "Stripe test key must be detected");

    let stripe = stripe.unwrap();
    assert!(stripe.confidence_level.is_some());

    // Zero Leak Policy: test key must be at minimum Suspicious
    assert!(
        stripe.confidence_level.unwrap() >= ConfidenceLevel::Suspicious,
        "Stripe test key must be >= Suspicious (Zero Leak Policy), got {:?}",
        stripe.confidence_level
    );

    // Must NEVER be Info
    assert_ne!(
        stripe.confidence_level.unwrap(),
        ConfidenceLevel::Info,
        "Stripe test key must never be Info"
    );
}

/// Test: Stripe live key gets Critical
#[test]
fn e2e_confidence_scoring_stripe_live_key() {
    let config = VelkaConfig::default();
    let fake_live_stripe = format!("sk_live_{}", "b".repeat(24));
    let content = format!(r#"STRIPE_KEY="{fake_live_stripe}""#);

    let sins = scan_content(&content, &config).unwrap();
    let stripe = sins.iter().find(|s| s.rule_id == "STRIPE_SECRET");
    assert!(stripe.is_some(), "Stripe live key must be detected");

    let stripe = stripe.unwrap();
    assert_eq!(
        stripe.confidence_level.unwrap(),
        ConfidenceLevel::Critical,
        "Stripe live key must be Critical"
    );
}

/// Test: Structural validators enforce Zero Leak Policy at the type level
#[test]
fn e2e_zero_leak_policy_type_safety() {
    // Even if score derives Info, enforce_zero_leak_floor promotes to Suspicious
    let info = ConfidenceLevel::Info;
    let floored = structural_validators::enforce_zero_leak_floor(info);
    assert_eq!(floored, ConfidenceLevel::Suspicious);

    // Critical stays Critical
    let critical = ConfidenceLevel::Critical;
    let floored = structural_validators::enforce_zero_leak_floor(critical);
    assert_eq!(floored, ConfidenceLevel::Critical);
}

/// Test: ML ensemble influences `ConfidenceLevel` derivation
#[test]
fn e2e_ml_ensemble_influences_confidence_level() {
    // AWS key with valid structure → ML should give high score → Critical
    let result = classify_default("AKIA1234567890ABCDEF", "AWS_ACCESS_KEY");
    let ml_level = ConfidenceLevel::from_score(result.score);
    assert!(
        ml_level >= ConfidenceLevel::Suspicious,
        "ML ensemble for valid AWS key should yield at least Suspicious, got {:?} (score: {})",
        ml_level,
        result.score
    );

    // Low-entropy string → ML should give low score → Info
    let result = classify_default("aaaaaaaaaa", "HIGH_ENTROPY");
    let ml_level = ConfidenceLevel::from_score(result.score);
    assert_eq!(
        ml_level,
        ConfidenceLevel::Info,
        "Low-entropy string should be Info"
    );
}

/// Test: Disabled rules are respected
#[test]
fn e2e_disabled_rules() {
    let mut config = VelkaConfig::default();
    config.rules.disable = vec!["AWS_ACCESS_KEY".to_string()];
    let content = r#"let key = "AKIA0000000000000000";"#;
    let sins = scan_content(content, &config).unwrap();
    assert!(
        sins.iter().all(|s| s.rule_id != "AWS_ACCESS_KEY"),
        "Disabled rule AWS_ACCESS_KEY should not trigger"
    );
}
