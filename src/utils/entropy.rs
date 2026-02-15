/// Shannon entropy in bits per byte. Returns 0.0 for empty strings.
/// Typical values: low (<2.0) for natural text, high (>4.5) for random/secret-like strings.
#[must_use]
pub fn calculate_entropy(s: &str) -> f32 {
    let len = s.len();
    if len == 0 {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    let len_f32 = len as f32;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f32 / len_f32;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_uniform_low() {
        let s = "aaaa";
        let e = calculate_entropy(s);
        assert!((e - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_entropy_high() {
        let s = "abcdefghijklmnopqrstuvwxyz0123456789";
        let e = calculate_entropy(s);
        assert!(e > 4.0);
    }

    #[test]
    fn test_entropy_repeated_char() {
        let e = calculate_entropy("aaaaaaaaaa");
        assert_eq!(e, 0.0);
    }
}
