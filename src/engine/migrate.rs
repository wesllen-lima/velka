use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::engine::RULES;
use crate::error::{Result, VelkaError};
use crate::output::{env_var_for_rule, suggest_remediation};

#[derive(Debug, Clone, Default)]
pub struct MigrateReport {
    pub migrated_count: usize,
    pub files_updated: Vec<String>,
    pub vars_added: Vec<String>,
    pub skipped_unable_extract: usize,
    pub skipped_key_present: usize,
}

fn extract_secret_value(snippet: &str, rule_id: &str) -> Option<String> {
    let rule = RULES.iter().find(|r| r.id == rule_id)?;
    let mat = rule.pattern.find(snippet)?;
    let matched = mat.as_str();
    if matched.len() > 4096 {
        return None;
    }
    Some(matched.to_string())
}

fn escape_env_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    let need_quotes = value.contains('\n') || value.contains('#') || value.contains(' ');
    if need_quotes {
        out.push('"');
    }
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    if need_quotes {
        out.push('"');
    }
    out
}

fn env_file_keys(path: &Path) -> std::collections::HashSet<String> {
    let Ok(content) = fs::read_to_string(path) else {
        return std::collections::HashSet::new();
    };
    let mut keys = std::collections::HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            if !key.is_empty() {
                keys.insert(key);
            }
        }
    }
    keys
}

#[cfg(unix)]
fn set_file_mode_0600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode_0600(_path: &Path) -> Result<()> {
    Ok(())
}

#[must_use]
pub fn check_env_in_gitignore(repo_root: &Path, env_path: &Path) -> bool {
    let gitignore = repo_root.join(".gitignore");
    let Ok(content) = fs::read_to_string(&gitignore) else {
        return false;
    };
    let env_name = env_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(".env");
    for line in content.lines() {
        let line = line.trim().strip_prefix('#').unwrap_or(line).trim();
        if line == ".env" || line == env_name || line.ends_with("/.env") {
            return true;
        }
    }
    false
}

pub fn check_env_tracked(repo_root: &Path, env_path: &Path) -> Result<bool> {
    let Ok(repo) = git2::Repository::open(repo_root) else {
        return Ok(false);
    };
    let rel = env_path
        .strip_prefix(repo_root)
        .unwrap_or(env_path);
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    let index = repo.index()?;
    Ok(index.get_path(Path::new(rel_str.as_str()), 0).is_some())
}

pub fn run_migrate(
    path: &Path,
    env_file: &Path,
    dry_run: bool,
    yes: bool,
) -> Result<MigrateReport> {
    let config = crate::config::VelkaConfig::load()?;
    let sins = crate::scan_with_config(path, &config)?;

    let env_path_for_check = if env_file.is_absolute() {
        env_file.to_path_buf()
    } else {
        path.join(env_file)
    };

    let path_canon = path.canonicalize().map_err(|e| VelkaError::InvalidPath(e.to_string()))?;
    let env_canon = env_path_for_check
        .canonicalize()
        .unwrap_or_else(|_| env_path_for_check.clone());
    if !env_canon.starts_with(&path_canon) {
        return Err(VelkaError::InvalidPath(
            "env file path must be inside scan path".to_string(),
        ));
    }
    if env_path_for_check.exists() {
        let tracked = check_env_tracked(path, &env_path_for_check).unwrap_or(false);
        if tracked {
            return Err(VelkaError::Config(
                ".env is tracked by Git; refuse to write secrets".to_string(),
            ));
        }
    } else if !dry_run {
        let in_ignore = check_env_in_gitignore(path, &env_path_for_check);
        if !in_ignore {
            return Err(VelkaError::Config(
                ".env is not in .gitignore; add .env to .gitignore first".to_string(),
            ));
        }
    }

    let existing_keys = env_file_keys(&env_path_for_check);
    let mut added_keys = existing_keys.clone();

    let mut report = MigrateReport::default();
    let mut to_append: Vec<(String, String)> = Vec::new();
    let mut file_edits: HashMap<PathBuf, Vec<(usize, String, String)>> = HashMap::new();

    for sin in &sins {
        let env_key = env_var_for_rule(&sin.rule_id).to_string();
        let suggested_line = suggest_remediation(sin);

        let Some(secret_value) = extract_secret_value(&sin.snippet, &sin.rule_id) else {
            report.skipped_unable_extract += 1;
            continue;
        };
        if added_keys.contains(&env_key) {
            report.skipped_key_present += 1;
            continue;
        }
        added_keys.insert(env_key.clone());
        to_append.push((env_key.clone(), secret_value));
        report.vars_added.push(env_key.clone());
        file_edits
            .entry(PathBuf::from(&sin.path))
            .or_default()
            .push((sin.line_number, sin.snippet.clone(), suggested_line));
    }

    if dry_run {
        report.migrated_count = to_append.len();
        for path_buf in file_edits.keys() {
            report.files_updated.push(path_buf.to_string_lossy().to_string());
        }
        return Ok(report);
    }

    if !yes && !to_append.is_empty() {
        return Err(VelkaError::Config(
            "run with --yes to apply migration, or use --dry-run to preview".to_string(),
        ));
    }

    if !to_append.is_empty() {
        let parent = env_path_for_check.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&env_path_for_check)?;
        for (key, value) in &to_append {
            let escaped = escape_env_value(value);
            let _ = writeln!(f, "{key}={escaped}");
        }
        f.sync_all()?;
        drop(f);
        set_file_mode_0600(&env_path_for_check)?;
        report.migrated_count = to_append.len();
    }

    for (file_path, edits) in file_edits {
        let full_path = path.join(&file_path);
        let content = fs::read_to_string(&full_path)?;
        let line_ending = if content.contains("\r\n") { "\r\n" } else { "\n" };
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        for (line_num, old_line, new_line) in edits {
            if line_num > 0 && line_num <= lines.len() {
                let idx = line_num - 1;
                if lines[idx].trim() == old_line.trim() {
                    lines[idx] = new_line;
                }
            }
        }
        let new_content = lines.join(line_ending);
        if new_content != content {
            fs::write(&full_path, new_content)?;
            report.files_updated.push(file_path.to_string_lossy().to_string());
        }
    }

    Ok(report)
}

#[must_use]
pub fn format_migrate_report(report: &MigrateReport) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "Migrated {} secret(s) to .env", report.migrated_count);
    if !report.files_updated.is_empty() {
        let _ = writeln!(out, "Files updated:");
        for f in &report.files_updated {
            let _ = writeln!(out, "  - {f}");
        }
    }
    if !report.vars_added.is_empty() {
        let _ = writeln!(out, "Variables added:");
        for v in &report.vars_added {
            let _ = writeln!(out, "  - {v}");
        }
    }
    if report.skipped_unable_extract > 0 {
        let _ = writeln!(out, "Skipped (unable to extract): {}", report.skipped_unable_extract);
    }
    if report.skipped_key_present > 0 {
        let _ = writeln!(out, "Skipped (key already present): {}", report.skipped_key_present);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_secret_value_simple() {
        let snippet = r#"const key = "AKIA0000000000000000";"#;
        let got = extract_secret_value(snippet, "AWS_ACCESS_KEY");
        assert!(got.is_some());
        assert!(!got.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_extract_secret_value_no_match() {
        let snippet = "const x = 42;";
        assert!(extract_secret_value(snippet, "AWS_ACCESS_KEY").is_none());
    }

    #[test]
    fn test_escape_env_value_no_special() {
        let out = escape_env_value("simple");
        assert_eq!(out, "simple");
    }

    #[test]
    fn test_escape_env_value_newline() {
        let out = escape_env_value("a\nb");
        assert!(out.contains('"'));
        assert!(out.contains("\\n"));
        assert!(!out.contains('\n'));
    }

    #[test]
    fn test_escape_env_value_backslash() {
        let out = escape_env_value("a\\b");
        assert!(out.contains("\\\\"));
    }
}
