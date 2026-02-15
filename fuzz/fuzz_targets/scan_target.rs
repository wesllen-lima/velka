#![no_main]

use libfuzzer_sys::fuzz_target;
use velka::engine::ml_classifier::{classify_default, EnsembleWeights, classify};
use velka::{VelkaConfig, engine::scan_content};

fuzz_target!(|data: &[u8]| {
    // Fuzz scan_content with arbitrary byte sequences interpreted as UTF-8
    if let Ok(text) = std::str::from_utf8(data) {
        let config = VelkaConfig::default();
        let _ = scan_content(text, &config);
    }
});
