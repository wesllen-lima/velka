use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::Sin;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEntry {
    pub rule_id: String,
    pub snippet_hash: String,
    pub file_pattern: String,
    pub is_false_positive: bool,
    pub created_at: String,
}

#[derive(Debug)]
pub struct FeedbackStore {
    path: PathBuf,
    entries: Vec<FeedbackEntry>,
}

impl FeedbackStore {
    fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".velka")
            .join("feedback.json")
    }

    pub fn load() -> crate::error::Result<Self> {
        let path = Self::default_path();
        let entries = if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(Self { path, entries })
    }

    pub fn save(&self) -> crate::error::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.entries)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    pub fn mark_false_positive(&mut self, sin: &Sin) -> crate::error::Result<()> {
        let snippet_hash = Self::hash_snippet(&sin.snippet);
        let file_pattern = Self::extract_file_pattern(&sin.path);

        if self.entries.iter().any(|e| {
            e.snippet_hash == snippet_hash
                && e.rule_id == sin.rule_id
                && e.file_pattern == file_pattern
        }) {
            return Ok(());
        }

        self.entries.push(FeedbackEntry {
            rule_id: sin.rule_id.clone(),
            snippet_hash,
            file_pattern,
            is_false_positive: true,
            created_at: chrono::Utc::now().to_rfc3339(),
        });

        self.save()
    }

    #[must_use]
    pub fn is_known_false_positive(&self, sin: &Sin) -> bool {
        let snippet_hash = Self::hash_snippet(&sin.snippet);
        self.entries.iter().any(|e| {
            e.is_false_positive && e.snippet_hash == snippet_hash && e.rule_id == sin.rule_id
        })
    }

    #[must_use]
    pub fn entries(&self) -> &[FeedbackEntry] {
        &self.entries
    }

    pub fn clear(&mut self) -> crate::error::Result<()> {
        self.entries.clear();
        self.save()
    }

    fn hash_snippet(snippet: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(snippet.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn extract_file_pattern(path: &str) -> String {
        if let Some(ext) = std::path::Path::new(path).extension().and_then(|e| e.to_str()) {
            format!("*.{ext}")
        } else {
            "*".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Severity, Sin};

    fn make_sin(rule_id: &str, snippet: &str) -> Sin {
        Sin {
            path: "test.rs".to_string(),
            line_number: 10,
            snippet: snippet.to_string(),
            context: vec![],
            severity: Severity::Mortal,
            description: "test".to_string(),
            rule_id: rule_id.to_string(),
            commit_hash: None,
            verified: None,
            confidence: None,
            confidence_factors: None,
            confidence_level: None,
            verification_detail: None,
        }
    }

    #[test]
    fn test_mark_and_detect_false_positive() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("feedback.json");
        let mut store = FeedbackStore {
            path,
            entries: vec![],
        };

        let sin = make_sin("AWS_ACCESS_KEY", "AKIA0000000000000000");
        assert!(!store.is_known_false_positive(&sin));

        store.mark_false_positive(&sin).unwrap();
        assert!(store.is_known_false_positive(&sin));

        // Different snippet should not match
        let other = make_sin("AWS_ACCESS_KEY", "AKIA1111111111111111");
        assert!(!store.is_known_false_positive(&other));
    }

    #[test]
    fn test_clear_removes_all() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("feedback.json");
        let mut store = FeedbackStore {
            path,
            entries: vec![],
        };

        let sin = make_sin("AWS_ACCESS_KEY", "AKIA0000000000000000");
        store.mark_false_positive(&sin).unwrap();
        assert!(!store.entries.is_empty());

        store.clear().unwrap();
        assert!(store.entries.is_empty());
        assert!(!store.is_known_false_positive(&sin));
    }

    #[test]
    fn test_no_duplicate_entries() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("feedback.json");
        let mut store = FeedbackStore {
            path,
            entries: vec![],
        };

        let sin = make_sin("AWS_ACCESS_KEY", "AKIA0000000000000000");
        store.mark_false_positive(&sin).unwrap();
        store.mark_false_positive(&sin).unwrap();
        assert_eq!(store.entries.len(), 1);
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("feedback.json");
        let mut store = FeedbackStore {
            path: path.clone(),
            entries: vec![],
        };

        let sin = make_sin("GITHUB_TOKEN", "ghp_abc123");
        store.mark_false_positive(&sin).unwrap();

        // Load from disk
        let loaded = FeedbackStore {
            path: path.clone(),
            entries: {
                let content = std::fs::read_to_string(&path).unwrap();
                serde_json::from_str(&content).unwrap()
            },
        };

        assert!(loaded.is_known_false_positive(&sin));
    }

    #[test]
    fn test_not_false_positive_different_snippet() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("feedback.json");
        let mut store = FeedbackStore {
            path,
            entries: vec![],
        };

        let sin = make_sin("AWS_ACCESS_KEY", "AKIA0000000000000000");
        store.mark_false_positive(&sin).unwrap();

        // Completely different snippet — should NOT be a known FP
        let other = make_sin("AWS_ACCESS_KEY", "AKIAZ999888777666555");
        assert!(!store.is_known_false_positive(&other));
    }

    #[test]
    fn test_mark_false_positive_idempotent_different_rule() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("feedback.json");
        let mut store = FeedbackStore {
            path,
            entries: vec![],
        };

        let sin_a = make_sin("AWS_ACCESS_KEY", "AKIA0000000000000000");
        let sin_b = make_sin("GENERIC_SECRET", "AKIA0000000000000000");

        store.mark_false_positive(&sin_a).unwrap();
        store.mark_false_positive(&sin_a).unwrap(); // idempotent
        store.mark_false_positive(&sin_b).unwrap(); // different rule_id → new entry

        assert_eq!(store.entries.len(), 2);
        assert!(store.is_known_false_positive(&sin_a));
        assert!(store.is_known_false_positive(&sin_b));
    }
}
