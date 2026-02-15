use std::cell::RefCell;
use std::path::Path;
use std::sync::Arc;

use crate::error::Result;
use crossbeam_channel::Sender;
use git2::{DiffOptions, Oid, Repository};
use rayon::prelude::*;

use crate::config::VelkaConfig;
use crate::domain::Sin;
use crate::engine::analyzer::{analyze_line, AnalyzeLineConfig};
use crate::engine::rules::CompiledCustomRule;

pub fn scan_history(repo_path: &Path, config: &VelkaConfig, sender: &Sender<Sin>) -> Result<()> {
    let repo = Repository::open(repo_path)?;

    let custom_rules = config.compile_custom_rules()?;
    let custom_rules: Arc<Vec<CompiledCustomRule>> = Arc::new(custom_rules);

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;

    let entropy_threshold = config.scan.entropy_threshold;
    let disabled_rules: Arc<Vec<String>> = Arc::new(config.rules.disable.clone());
    let whitelist: Arc<Vec<String>> = Arc::new(config.scan.whitelist.clone());

    let commit_oids: Vec<Oid> = revwalk.filter_map(std::result::Result::ok).collect();
    let repo_path_arc = Arc::new(repo_path.to_path_buf());

    commit_oids.par_iter().try_for_each(|&oid| -> Result<()> {
        let repo = Repository::open(repo_path_arc.as_path())?;
        let commit = repo.find_commit(oid)?;

        if commit.parent_count() == 0 {
            return Ok(());
        }

        let parent = commit.parent(0)?;
        let parent_tree = parent.tree()?;
        let commit_tree = commit.tree()?;

        let mut diff_opts = DiffOptions::new();
        diff_opts.context_lines(1);
        diff_opts.minimal(true);

        let diff =
            repo.diff_tree_to_tree(Some(&parent_tree), Some(&commit_tree), Some(&mut diff_opts))?;

        let commit_hash = oid.to_string();
        let short_hash = commit_hash.chars().take(8).collect::<String>();

        let hunk_context = RefCell::new(Vec::<String>::new());
        let current_file_path = RefCell::new(String::new());

        let disabled = Arc::clone(&disabled_rules);
        let wl = Arc::clone(&whitelist);
        let custom = Arc::clone(&custom_rules);

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
                    .map_or_else(|| "unknown".to_string(), std::string::ToString::to_string);

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
                let line_content = match std::str::from_utf8(content_bytes) {
                    Ok(s) => s.trim_end(),
                    Err(_) => return true,
                };

                let mut hunk_ctx = hunk_context.borrow_mut();

                if origin == '+' {
                    let trimmed = line_content.trim();
                    if trimmed.is_empty() {
                        hunk_ctx.push(line_content.to_string());
                    } else {
                        let line_num = line.new_lineno().unwrap_or(0) as usize;
                        let ctx_len = hunk_ctx.len();

                        let mut ctx_lines = Vec::with_capacity(3);
                        if ctx_len > 0 {
                            ctx_lines.push(hunk_ctx[ctx_len - 1].clone());
                        } else {
                            ctx_lines.push(String::new());
                        }
                        ctx_lines.push(line_content.to_string());
                        ctx_lines.push(String::new());

                        drop(hunk_ctx);

                        let file_path = current_file_path.borrow().clone();
                        let adaptive_threshold = if let Some(ext) = std::path::Path::new(&file_path)
                            .extension()
                            .and_then(|e| e.to_str())
                        {
                            match ext {
                                "js" | "min.js" | "min.css" => entropy_threshold + 0.5,
                                "env" | "config" | "properties" | "ini" => entropy_threshold - 0.3,
                                "json" | "yaml" | "yml" | "toml" => entropy_threshold - 0.2,
                                _ => entropy_threshold,
                            }
                        } else {
                            entropy_threshold
                        };
                        let scan_cfg = AnalyzeLineConfig {
                            entropy_threshold: adaptive_threshold,
                            disabled_rules: &disabled,
                            whitelist: &wl,
                            custom_rules: &custom,
                            skip_entropy_in_regex_context: true,
                            allowlist_regexes: None,
                        };

                        let ctx_refs: [&str; 3] = [&ctx_lines[0], &ctx_lines[1], &ctx_lines[2]];
                        if let Some(sin) = analyze_line(
                            trimmed,
                            &file_path,
                            line_num,
                            ctx_refs,
                            Some(short_hash.clone()),
                            &scan_cfg,
                        ) {
                            if sender.send(sin).is_err() {
                                return false;
                            }
                        }

                        hunk_context.borrow_mut().push(line_content.to_string());
                    }
                } else if origin == ' ' {
                    hunk_ctx.push(line_content.to_string());
                }

                true
            }),
        )?;
        Ok(())
    })?;

    Ok(())
}
