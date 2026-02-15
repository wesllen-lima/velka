#![no_main]

use libfuzzer_sys::fuzz_target;
use velka::engine::ml_classifier::{classify, classify_default, EnsembleWeights};

static RULE_IDS: &[&str] = &[
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "GITHUB_TOKEN",
    "STRIPE_SECRET",
    "OPENAI_API_KEY",
    "JWT_TOKEN",
    "PRIVATE_KEY",
    "HIGH_ENTROPY",
    "GENERIC_API_KEY",
    "GENERIC_SECRET",
    "SUPABASE_ANON_KEY",
    "SENDGRID_API",
    "NPM_TOKEN",
    "UNKNOWN_RULE",
];

fuzz_target!(|data: &[u8]| {
    if let Ok(candidate) = std::str::from_utf8(data) {
        // Fuzz classify_default with all known rule IDs
        for rule_id in RULE_IDS {
            let result = classify_default(candidate, rule_id);
            // Ensure score is always in valid range
            assert!(result.score >= 0.0 && result.score <= 1.0,
                "Score out of range: {} for rule {}", result.score, rule_id);
        }

        // Fuzz with extreme weight values
        if data.len() >= 16 {
            let weights = EnsembleWeights {
                entropy: f32::from_le_bytes([data[0], data[1], data[2], data[3]]).abs().min(100.0),
                char_frequency: f32::from_le_bytes([data[4], data[5], data[6], data[7]]).abs().min(100.0),
                structural: f32::from_le_bytes([data[8], data[9], data[10], data[11]]).abs().min(100.0),
                length: f32::from_le_bytes([data[12], data[13], data[14], data[15]]).abs().min(100.0),
            };
            // Only test with finite weights
            if weights.entropy.is_finite()
                && weights.char_frequency.is_finite()
                && weights.structural.is_finite()
                && weights.length.is_finite()
                && (weights.entropy + weights.char_frequency + weights.structural + weights.length) > 0.0
            {
                let _ = classify(candidate, "AWS_ACCESS_KEY", &weights);
            }
        }
    }
});
