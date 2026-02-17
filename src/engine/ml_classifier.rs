//! ML-enhanced ensemble classifier for secret candidate scoring.
//!
//! Combines four signals — Shannon entropy, character frequency distribution,
//! structural validation (prefix, length, charset) and length heuristics —
//! into a single confidence score in `[0.0, 1.0]`.
//!
//! Use [`classify_default`] for the common case with default weights,
//! or [`classify`] to supply custom [`EnsembleWeights`].

use crate::engine::rules::RULES;
use crate::utils::calculate_entropy;

/// Result of the ML-enhanced classification ensemble.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// Final combined score in [0.0, 1.0].
    pub score: f32,
    /// Whether the classifier considers this a true positive.
    pub is_secret: bool,
    /// Individual factor contributions.
    pub factors: Vec<(&'static str, f32)>,
}

/// Weights for the ensemble scoring model.
#[derive(Debug, Clone)]
pub struct EnsembleWeights {
    pub entropy: f32,
    pub char_frequency: f32,
    pub structural: f32,
    pub length: f32,
}

impl Default for EnsembleWeights {
    fn default() -> Self {
        Self {
            entropy: 0.35,
            char_frequency: 0.25,
            structural: 0.25,
            length: 0.15,
        }
    }
}

/// Classify a candidate string using the ensemble scoring model.
///
/// Combines entropy analysis, character frequency distribution,
/// structural validation (JWT, AWS, etc.), and length heuristics.
#[must_use]
pub fn classify(candidate: &str, rule_id: &str, weights: &EnsembleWeights) -> ClassificationResult {
    let entropy_score = score_entropy(candidate);
    let char_freq_score = score_char_frequency(candidate);
    let structural_score = score_structural(candidate, rule_id);
    let length_score = score_length(candidate, rule_id);

    // Weighted average across all scoring dimensions.
    // Each factor is 0.0..1.0; weights control relative importance.
    let total_weight =
        weights.entropy + weights.char_frequency + weights.structural + weights.length;
    let combined = (entropy_score * weights.entropy
        + char_freq_score * weights.char_frequency
        + structural_score * weights.structural
        + length_score * weights.length)
        / total_weight;

    let factors = vec![
        ("entropy", entropy_score),
        ("char_frequency", char_freq_score),
        ("structural", structural_score),
        ("length", length_score),
    ];

    ClassificationResult {
        score: combined,
        is_secret: combined >= 0.55,
        factors,
    }
}

/// Classify using default weights.
#[must_use]
pub fn classify_default(candidate: &str, rule_id: &str) -> ClassificationResult {
    classify(candidate, rule_id, &EnsembleWeights::default())
}

/// Entropy-based scoring. Maps Shannon entropy to [0, 1].
fn score_entropy(candidate: &str) -> f32 {
    let entropy = calculate_entropy(candidate);
    // Normalize: entropy < 2.0 = low, > 5.0 = very high
    ((entropy - 2.0) / 3.5).clamp(0.0, 1.0)
}

/// Character frequency distribution scoring.
/// Secrets tend to have more uniform distributions across character classes.
fn score_char_frequency(candidate: &str) -> f32 {
    if candidate.is_empty() {
        return 0.0;
    }

    let len = candidate.len() as f32;
    let mut upper = 0u32;
    let mut lower = 0u32;
    let mut digit = 0u32;
    let mut special = 0u32;

    for ch in candidate.chars() {
        if ch.is_ascii_uppercase() {
            upper += 1;
        } else if ch.is_ascii_lowercase() {
            lower += 1;
        } else if ch.is_ascii_digit() {
            digit += 1;
        } else {
            special += 1;
        }
    }

    let ratios = [
        upper as f32 / len,
        lower as f32 / len,
        digit as f32 / len,
        special as f32 / len,
    ];

    // Count how many character classes are represented (> 5% each)
    let classes_present = ratios.iter().filter(|&&r| r > 0.05).count();

    // More classes = more likely a secret
    let class_score = match classes_present {
        0 | 1 => 0.1,
        2 => 0.4,
        3 => 0.75,
        4 => 0.95,
        _ => 0.5,
    };

    // Penalize if any single class dominates >90%
    let max_ratio = ratios.iter().copied().fold(0.0f32, f32::max);
    if max_ratio > 0.90 {
        return class_score * 0.3;
    }

    class_score
}

/// Structural validation scoring.
/// Uses rule metadata (prefix, length, charset) for generic scoring.
/// Falls back to 0.5 for rules without metadata.
fn score_structural(candidate: &str, rule_id: &str) -> f32 {
    let Some(rule) = RULES.iter().find(|r| r.id == rule_id) else {
        return 0.5;
    };

    let mut score = 0.5f32;

    if let Some(prefix) = rule.required_prefix {
        if candidate.starts_with(prefix) {
            score += 0.25;
        } else {
            score -= 0.3;
        }
    }

    if let Some((min, max)) = rule.expected_len {
        let len = candidate.len();
        if len >= min && len <= max {
            score += 0.2;
        } else {
            score -= 0.2;
        }
    }

    if let Some(charset) = rule.charset {
        let matches_charset = match charset {
            "alphanum" => candidate.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "base64" => candidate.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '_' || c == '-' || c == '.'),
            "hex" => candidate.chars().all(|c| c.is_ascii_hexdigit()),
            _ => true,
        };
        if matches_charset {
            score += 0.1;
        } else {
            score -= 0.1;
        }
    }

    score.clamp(0.0, 1.0)
}

/// Length-based scoring. Uses rule metadata for expected length ranges.
fn score_length(candidate: &str, rule_id: &str) -> f32 {
    let len = candidate.len();

    let (ideal_min, ideal_max) = RULES
        .iter()
        .find(|r| r.id == rule_id)
        .and_then(|r| r.expected_len)
        .unwrap_or((16, 500));

    if len >= ideal_min && len <= ideal_max {
        1.0
    } else if len < ideal_min {
        let ratio = len as f32 / ideal_min as f32;
        ratio.clamp(0.0, 1.0)
    } else {
        let over = (len - ideal_max) as f32 / ideal_max as f32;
        (1.0 - over * 0.5).clamp(0.1, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_aws_key_high_confidence() {
        let result = classify_default("AKIA1234567890ABCDEF", "AWS_ACCESS_KEY");
        assert!(result.is_secret);
        assert!(result.score > 0.6);
    }

    #[test]
    fn test_classify_jwt_token() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz";
        let result = classify_default(jwt, "JWT_TOKEN");
        assert!(result.is_secret);
        assert!(result.score > 0.5);
    }

    #[test]
    fn test_classify_low_entropy_string() {
        let result = classify_default("aaaaaaaaaa", "HIGH_ENTROPY");
        assert!(!result.is_secret);
        assert!(result.score < 0.5);
    }

    #[test]
    fn test_classify_github_token() {
        let token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
        let result = classify_default(token, "GITHUB_TOKEN");
        assert!(result.is_secret);
        assert!(result.score > 0.6);
    }

    #[test]
    fn test_char_frequency_uniform() {
        let score = score_char_frequency("aB3$kL9mN2pQ5r");
        assert!(score > 0.5);
    }

    #[test]
    fn test_char_frequency_single_class() {
        let score = score_char_frequency("AAAAAAAAAAAA");
        assert!(score < 0.2);
    }

    #[test]
    fn test_structural_jwt_valid() {
        let score = score_structural(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "JWT_TOKEN",
        );
        assert!(score > 0.5, "JWT structural score should be moderate-high, got {score}");
    }

    #[test]
    fn test_structural_aws_valid() {
        let score = score_structural("AKIA1234567890ABCDEF", "AWS_ACCESS_KEY");
        assert!(score > 0.8, "AWS structural score should be high, got {score}");
    }

    #[test]
    fn test_length_scoring_exact() {
        let score = score_length("AKIA1234567890ABCDEF", "AWS_ACCESS_KEY");
        assert!((score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_length_scoring_too_short() {
        let score = score_length("AKIA12", "AWS_ACCESS_KEY");
        assert!(score < 0.5);
    }
}
