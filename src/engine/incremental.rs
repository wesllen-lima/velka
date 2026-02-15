use std::path::{Path, PathBuf};

use crate::error::Result;
use git2::{DiffOptions, Repository, StatusOptions};

pub fn get_changed_files(repo_path: &Path) -> Result<Vec<PathBuf>> {
    let repo = Repository::open(repo_path)?;

    let head = repo.head()?.peel_to_tree()?;

    let mut diff_opts = DiffOptions::new();
    diff_opts.include_untracked(true);
    diff_opts.recurse_untracked_dirs(true);

    let diff = repo.diff_tree_to_workdir_with_index(Some(&head), Some(&mut diff_opts))?;

    let mut files = Vec::new();

    diff.foreach(
        &mut |delta, _| {
            if let Some(path) = delta.new_file().path() {
                files.push(repo_path.join(path));
            }
            true
        },
        None,
        None,
        None,
    )?;

    Ok(files)
}

pub fn get_staged_files(repo_path: &Path) -> Result<Vec<PathBuf>> {
    let repo = Repository::open(repo_path)?;

    let mut status_opts = StatusOptions::new();
    status_opts.include_untracked(false);
    status_opts.include_ignored(false);

    let statuses = repo.statuses(Some(&mut status_opts))?;

    let mut files = Vec::new();

    for entry in statuses.iter() {
        let status = entry.status();

        let is_staged = status.is_index_new()
            || status.is_index_modified()
            || status.is_index_renamed()
            || status.is_index_typechange();

        if is_staged {
            if let Some(path) = entry.path() {
                files.push(repo_path.join(path));
            }
        }
    }

    Ok(files)
}

pub fn get_changed_files_since(repo_path: &Path, since_ref: &str) -> Result<Vec<PathBuf>> {
    let repo = Repository::open(repo_path)?;

    let since_obj = repo
        .revparse_single(since_ref)
        .map_err(|e| git2::Error::from_str(&format!("Cannot resolve '{since_ref}': {e}")))?;
    let since_tree = since_obj
        .peel_to_commit()
        .map_err(|e| git2::Error::from_str(&format!("'{since_ref}' is not a commit: {e}")))?
        .tree()?;

    let head_tree = repo.head()?.peel_to_tree()?;

    let mut diff_opts = DiffOptions::new();
    let diff = repo.diff_tree_to_tree(Some(&since_tree), Some(&head_tree), Some(&mut diff_opts))?;

    let mut files = Vec::new();
    diff.foreach(
        &mut |delta, _| {
            if let Some(path) = delta.new_file().path() {
                let full = repo_path.join(path);
                if full.exists() {
                    files.push(full);
                }
            }
            true
        },
        None,
        None,
        None,
    )?;

    Ok(files)
}

pub fn get_diff_line_ranges_since(
    repo_path: &Path,
    since_ref: &str,
) -> Result<std::collections::HashMap<PathBuf, Vec<(usize, usize)>>> {
    let repo = Repository::open(repo_path)?;

    let since_obj = repo
        .revparse_single(since_ref)
        .map_err(|e| git2::Error::from_str(&format!("Cannot resolve '{since_ref}': {e}")))?;
    let since_tree = since_obj
        .peel_to_commit()
        .map_err(|e| git2::Error::from_str(&format!("'{since_ref}' is not a commit: {e}")))?
        .tree()?;

    let head_tree = repo.head()?.peel_to_tree()?;

    let mut diff_opts = DiffOptions::new();
    let diff = repo.diff_tree_to_tree(Some(&since_tree), Some(&head_tree), Some(&mut diff_opts))?;

    let mut ranges: std::collections::HashMap<PathBuf, Vec<(usize, usize)>> =
        std::collections::HashMap::new();

    diff.foreach(
        &mut |_, _| true,
        None,
        Some(&mut |delta, hunk| {
            if let Some(path) = delta.new_file().path() {
                let full = repo_path.join(path);
                let start = hunk.new_start() as usize;
                let end = start + hunk.new_lines() as usize;
                ranges.entry(full).or_default().push((start, end));
            }
            true
        }),
        None,
    )?;

    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_get_changed_files_no_repo() {
        let temp = TempDir::new().unwrap();
        let result = get_changed_files(temp.path());
        assert!(result.is_err());
    }
}
