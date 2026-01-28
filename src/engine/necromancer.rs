use std::path::Path;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use git2::{DiffOptions, Repository};

use crate::domain::Sin;
use crate::engine::scanner::analyze_line;

pub fn scan_history(repo_path: &Path, sender: Sender<Sin>) -> Result<()> {
    let repo = Repository::open(repo_path)
        .context("Failed to open git repository")?;

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;

    for commit_id in revwalk {
        let oid = commit_id?;
        let commit = repo.find_commit(oid)?;

        if commit.parent_count() == 0 {
            continue;
        }

        let parent = commit.parent(0)?;
        let parent_tree = parent.tree()?;
        let commit_tree = commit.tree()?;

        let mut diff_opts = DiffOptions::new();
        diff_opts.context_lines(1);
        diff_opts.minimal(true);

        let diff = repo
            .diff_tree_to_tree(Some(&parent_tree), Some(&commit_tree), Some(&mut diff_opts))
            .context("Failed to create diff")?;

        let commit_hash = oid.to_string();
        let short_hash = commit_hash.chars().take(8).collect::<String>();

        use std::cell::RefCell;
        let hunk_context = RefCell::new(Vec::<String>::new());
        let current_file_path = RefCell::new(String::new());

        diff.foreach(
            &mut |delta, _| {
                if delta.flags().is_binary() {
                    return true;
                }

                *current_file_path.borrow_mut() = delta
                    .new_file()
                    .path()
                    .or_else(|| delta.old_file().path())
                    .and_then(|p| p.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                true
            },
            None,
            Some(&mut |_delta, _hunk| {
                hunk_context.borrow_mut().clear();
                true
            }),
            Some(&mut |_delta, _hunk, line| {
                let origin = line.origin();
                let content_bytes = line.content();
                let content = match std::str::from_utf8(content_bytes) {
                    Ok(s) => s.trim_end(),
                    Err(_) => return true,
                };

                let mut hunk_ctx = hunk_context.borrow_mut();

                if origin == '+' {
                    let trimmed = content.trim();
                    if !trimmed.is_empty() {
                        let line_num = line.new_lineno().unwrap_or(0) as usize;
                        let ctx_len = hunk_ctx.len();

                        let mut context = Vec::with_capacity(3);
                        if ctx_len > 0 {
                            context.push(hunk_ctx[ctx_len - 1].clone());
                        } else {
                            context.push(String::new());
                        }
                        context.push(content.to_string());
                        context.push(String::new());

                        drop(hunk_ctx);

                        let file_path = current_file_path.borrow().clone();

                        if let Some(sin) = analyze_line(
                            trimmed,
                            &file_path,
                            line_num,
                            context,
                            Some(short_hash.clone()),
                            4.6,
                            &[],
                        ) {
                            if sender.send(sin).is_err() {
                                return false;
                            }
                        }

                        hunk_context.borrow_mut().push(content.to_string());
                    } else {
                        hunk_ctx.push(content.to_string());
                    }
                } else if origin == ' ' {
                    hunk_ctx.push(content.to_string());
                }

                true
            }),
        )
        .context("Failed to process diff")?;
    }

    Ok(())
}
