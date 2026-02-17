use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::CacheLocation;

const CACHE_EXT: &str = "bincode";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub file_hash: String,
    pub rule_matches: Vec<CachedMatch>,
    pub scanned_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMatch {
    pub line_number: usize,
    pub rule_id: String,
    pub severity: String,
}

#[derive(Debug)]
pub struct ScanCache {
    entries: HashMap<String, CacheEntry>,
    project_path: Option<PathBuf>,
    user_path: Option<PathBuf>,
    modified: bool,
}

impl ScanCache {
    #[must_use]
    pub fn new(location: &CacheLocation, project_root: &Path) -> Self {
        let project_path = match location {
            CacheLocation::Project | CacheLocation::Both => Some(
                project_root
                    .join(".velka-cache")
                    .join(format!("cache.{CACHE_EXT}")),
            ),
            CacheLocation::User => None,
        };

        let user_path = match location {
            CacheLocation::User | CacheLocation::Both => ProjectDirs::from("", "", "velka")
                .map(|d| d.cache_dir().join(format!("scan_cache.{CACHE_EXT}"))),
            CacheLocation::Project => None,
        };

        let mut cache = Self {
            entries: HashMap::new(),
            project_path,
            user_path,
            modified: false,
        };

        cache.load();
        cache
    }

    fn load(&mut self) {
        if let Some(ref path) = self.project_path {
            if let Some(entries) = Self::load_from_file(path) {
                self.entries.extend(entries);
            }
        }

        if let Some(ref path) = self.user_path {
            if let Some(entries) = Self::load_from_file(path) {
                self.entries.extend(entries);
            }
        }
    }

    fn load_from_file(path: &Path) -> Option<HashMap<String, CacheEntry>> {
        let content = fs::read(path).ok()?;
        bincode::deserialize(&content).ok()
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        if !self.modified {
            return Ok(());
        }

        if let Some(ref path) = self.project_path {
            self.save_to_file(path)?;
        }

        if let Some(ref path) = self.user_path {
            self.save_to_file(path)?;
        }

        Ok(())
    }

    fn save_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = bincode::serialize(&self.entries).map_err(std::io::Error::other)?;
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, &content)?;
        fs::rename(tmp_path, path)
    }

    #[must_use]
    pub fn get(&self, file_path: &str, current_hash: &str) -> Option<&CacheEntry> {
        self.entries
            .get(file_path)
            .filter(|entry| entry.file_hash == current_hash)
    }

    pub fn insert(&mut self, file_path: String, entry: CacheEntry) {
        self.entries.insert(file_path, entry);
        self.modified = true;
    }

    pub fn insert_batch(&mut self, entries: impl IntoIterator<Item = (String, CacheEntry)>) {
        for (path, entry) in entries {
            self.entries.insert(path, entry);
        }
        self.modified = true;
    }

    #[must_use]
    pub fn hash_content(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    pub fn clear_project_cache(&mut self) {
        if let Some(ref path) = self.project_path {
            let _ = fs::remove_file(path);
        }
        self.entries.clear();
        self.modified = true;
    }
}

impl Drop for ScanCache {
    fn drop(&mut self) {
        let _ = self.save();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_hash_content() {
        let content = b"test content";
        let hash = ScanCache::hash_content(content);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_cache_insert_and_get() {
        let temp = TempDir::new().unwrap();
        let mut cache = ScanCache::new(&CacheLocation::Project, temp.path());

        let entry = CacheEntry {
            file_hash: "abc123".to_string(),
            rule_matches: vec![],
            scanned_at: 0,
        };

        cache.insert("test.rs".to_string(), entry.clone());

        let result = cache.get("test.rs", "abc123");
        assert!(result.is_some());

        let result = cache.get("test.rs", "wrong_hash");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_save_and_reload() {
        let temp = TempDir::new().unwrap();

        {
            let mut cache = ScanCache::new(&CacheLocation::Project, temp.path());
            let entry = CacheEntry {
                file_hash: "hash1".to_string(),
                rule_matches: vec![CachedMatch {
                    line_number: 10,
                    rule_id: "AWS_ACCESS_KEY".to_string(),
                    severity: "Mortal".to_string(),
                }],
                scanned_at: 1_234_567_890,
            };
            cache.insert("file1.rs".to_string(), entry);
            cache.save().unwrap();
        }

        // Reload cache from disk
        let cache2 = ScanCache::new(&CacheLocation::Project, temp.path());
        let result = cache2.get("file1.rs", "hash1");
        assert!(result.is_some());
        let entry = result.unwrap();
        assert_eq!(entry.rule_matches.len(), 1);
        assert_eq!(entry.rule_matches[0].rule_id, "AWS_ACCESS_KEY");
    }

    #[test]
    fn test_cache_insert_batch() {
        let temp = TempDir::new().unwrap();
        let mut cache = ScanCache::new(&CacheLocation::Project, temp.path());

        let entries = vec![
            (
                "a.rs".to_string(),
                CacheEntry {
                    file_hash: "h1".to_string(),
                    rule_matches: vec![],
                    scanned_at: 0,
                },
            ),
            (
                "b.rs".to_string(),
                CacheEntry {
                    file_hash: "h2".to_string(),
                    rule_matches: vec![],
                    scanned_at: 0,
                },
            ),
        ];

        cache.insert_batch(entries);
        assert!(cache.get("a.rs", "h1").is_some());
        assert!(cache.get("b.rs", "h2").is_some());
    }

    #[test]
    fn test_cache_clear_project() {
        let temp = TempDir::new().unwrap();
        let mut cache = ScanCache::new(&CacheLocation::Project, temp.path());

        cache.insert(
            "test.rs".to_string(),
            CacheEntry {
                file_hash: "h".to_string(),
                rule_matches: vec![],
                scanned_at: 0,
            },
        );
        cache.save().unwrap();

        cache.clear_project_cache();
        assert!(cache.get("test.rs", "h").is_none());
    }

    #[test]
    fn test_hash_content_deterministic() {
        let content = b"deterministic content";
        let h1 = ScanCache::hash_content(content);
        let h2 = ScanCache::hash_content(content);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_content_different_for_different_inputs() {
        let h1 = ScanCache::hash_content(b"content_a");
        let h2 = ScanCache::hash_content(b"content_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_cache_not_modified_initially() {
        let temp = TempDir::new().unwrap();
        let cache = ScanCache::new(&CacheLocation::Project, temp.path());
        // Save should be a no-op when not modified
        cache.save().unwrap();
    }
}
