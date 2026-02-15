use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::domain::{Severity, Sin};

const QUARANTINE_DIR: &str = ".velka/quarantine";

#[derive(Debug)]
pub struct QuarantineEntry {
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub rule_id: String,
    pub sha256: String,
}

#[must_use]
pub fn quarantine_dir(repo_root: &Path) -> PathBuf {
    repo_root.join(QUARANTINE_DIR)
}

pub fn ensure_quarantine_dir(repo_root: &Path) -> Result<PathBuf> {
    let dir = quarantine_dir(repo_root);
    fs::create_dir_all(&dir).with_context(|| format!("Failed to create {}", dir.display()))?;

    // Add .gitignore inside quarantine to prevent accidental commits
    let gitignore = dir.join(".gitignore");
    if !gitignore.exists() {
        fs::write(&gitignore, "*\n!.gitignore\n")?;
    }

    Ok(dir)
}

fn file_sha256(path: &Path) -> Result<String> {
    let content = fs::read(path).with_context(|| format!("Read {}", path.display()))?;
    let hash = Sha256::digest(&content);
    Ok(hex::encode(hash))
}

pub fn quarantine_file(repo_root: &Path, file_path: &Path) -> Result<QuarantineEntry> {
    let q_dir = ensure_quarantine_dir(repo_root)?;

    let sha = file_sha256(file_path)?;
    let relative = file_path.strip_prefix(repo_root).unwrap_or(file_path);

    // Flatten path: src/config/secrets.env -> src__config__secrets.env
    let flat_name = relative.to_string_lossy().replace(['/', '\\'], "__");

    let dest = q_dir.join(&flat_name);

    fs::copy(file_path, &dest)
        .with_context(|| format!("Copy {} -> {}", file_path.display(), dest.display()))?;
    fs::remove_file(file_path)
        .with_context(|| format!("Remove original {}", file_path.display()))?;

    // Write manifest entry
    let manifest = q_dir.join("manifest.log");
    let entry_line = format!(
        "{}\t{}\t{}\n",
        chrono::Utc::now().to_rfc3339(),
        relative.display(),
        sha
    );
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&manifest)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(entry_line.as_bytes())
        })?;

    Ok(QuarantineEntry {
        original_path: file_path.to_path_buf(),
        quarantine_path: dest,
        rule_id: String::new(),
        sha256: sha,
    })
}

pub fn restore_file(repo_root: &Path, quarantined_name: &str) -> Result<PathBuf> {
    let q_dir = quarantine_dir(repo_root);
    let src = q_dir.join(quarantined_name);

    if !src.exists() {
        anyhow::bail!("Quarantined file not found: {quarantined_name}");
    }

    let original_relative = quarantined_name.replace("__", "/");
    let dest = repo_root.join(&original_relative);

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::copy(&src, &dest)?;
    fs::remove_file(&src)?;

    Ok(dest)
}

pub fn list_quarantined(repo_root: &Path) -> Result<Vec<String>> {
    let q_dir = quarantine_dir(repo_root);
    if !q_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&q_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name != ".gitignore" && name != "manifest.log" {
            entries.push(name);
        }
    }
    entries.sort();
    Ok(entries)
}

/// Filter sins to only critical ones eligible for quarantine (Mortal severity).
#[must_use]
pub fn filter_quarantine_candidates(sins: &[Sin]) -> Vec<&Sin> {
    sins.iter()
        .filter(|s| s.severity == Severity::Mortal)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarantine_and_restore() {
        let tmp = tempfile::TempDir::new().unwrap();
        let secret_file = tmp.path().join("secret.env");
        fs::write(&secret_file, "DB_PASSWORD=hunter2").unwrap();

        let entry = quarantine_file(tmp.path(), &secret_file).unwrap();
        assert!(!secret_file.exists());
        assert!(entry.quarantine_path.exists());

        let flat = entry
            .quarantine_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let restored = restore_file(tmp.path(), &flat).unwrap();
        assert!(restored.exists());
        assert_eq!(
            fs::read_to_string(&restored).unwrap(),
            "DB_PASSWORD=hunter2"
        );
    }

    #[test]
    fn test_list_quarantined_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let list = list_quarantined(tmp.path()).unwrap();
        assert!(list.is_empty());
    }
}
