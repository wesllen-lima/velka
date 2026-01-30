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
