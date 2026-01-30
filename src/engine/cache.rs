use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::CacheLocation;

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
            CacheLocation::Project | CacheLocation::Both => {
                Some(project_root.join(".velka-cache").join("cache.json"))
            }
            CacheLocation::User => None,
        };

        let user_path = match location {
            CacheLocation::User | CacheLocation::Both => {
                ProjectDirs::from("", "", "velka").map(|d| d.cache_dir().join("scan_cache.json"))
            }
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
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
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
        let content = serde_json::to_string_pretty(&self.entries)?;
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
}
