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
