use sha2::{Digest, Sha256};

const BLOOM_BITS: usize = 1_000_000;
const BLOOM_BYTES: usize = BLOOM_BITS / 8 + 1;
const NUM_HASHES: usize = 3;

pub struct BloomFilter {
    bits: Vec<u8>,
}

impl BloomFilter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            bits: vec![0u8; BLOOM_BYTES],
        }
    }

    pub fn insert(&mut self, key: &[u8]) {
        for idx in Self::hash_indices(key) {
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    #[must_use]
    pub fn might_contain(&self, key: &[u8]) -> bool {
        Self::hash_indices(key)
            .iter()
            .all(|&idx| self.bits[idx / 8] & (1 << (idx % 8)) != 0)
    }

    fn hash_indices(key: &[u8]) -> [usize; NUM_HASHES] {
        let digest = Sha256::digest(key);
        let mut indices = [0usize; NUM_HASHES];
        for (i, idx) in indices.iter_mut().enumerate() {
            let offset = i * 8;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&digest[offset..offset + 8]);
            *idx = (u64::from_le_bytes(bytes) as usize) % BLOOM_BITS;
        }
        indices
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_check() {
        let mut bf = BloomFilter::new();
        bf.insert(b"hello");
        assert!(bf.might_contain(b"hello"));
    }

    #[test]
    fn test_no_false_negatives() {
        let mut bf = BloomFilter::new();
        let keys: Vec<String> = (0..1000).map(|i| format!("key_{i}")).collect();
        for k in &keys {
            bf.insert(k.as_bytes());
        }
        for k in &keys {
            assert!(bf.might_contain(k.as_bytes()), "False negative for {k}");
        }
    }

    #[test]
    fn test_probably_absent() {
        let bf = BloomFilter::new();
        assert!(!bf.might_contain(b"never_inserted"));
    }

    #[test]
    fn test_memory_size() {
        let bf = BloomFilter::new();
        assert!(bf.bits.len() <= 125_001); // ~125KB
    }
}
