use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::Result;
use crossbeam_channel::Sender;
use glob::Pattern;
use indicatif::{ProgressBar, ProgressStyle};

use crate::config::{compile_allowlist_file_patterns, compile_allowlist_regexes, VelkaConfig};
use regex::Regex;
use crate::domain::Severity;
use crate::domain::Sin;
use crate::engine::analyzer::{analyze_line, AnalyzeLineConfig};
use crate::engine::cache::{CacheEntry, CachedMatch, ScanCache};
use crate::engine::file_reader::{is_binary, read_file_content};
use crate::engine::rules::CompiledCustomRule;
use crate::engine::verifier::{self, compute_confidence};
use crate::utils::build_context;
use chrono::Utc;

#[derive(Debug, Clone, Copy)]
struct IgnoreRange {
    start: usize,
    end: usize,
}

fn compute_ignore_ranges(lines: &[&str]) -> Vec<IgnoreRange> {
    let mut ranges = Vec::new();
    let mut current_start: Option<usize> = None;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("velka:ignore-start") {
            if current_start.is_none() {
                current_start = Some(idx);
            }
        } else if trimmed.contains("velka:ignore-end") {
            if let Some(start) = current_start {
                ranges.push(IgnoreRange { start, end: idx });
                current_start = None;
            }
        }
    }

    ranges
}

fn get_entropy_threshold(path: &Path, base: f32) -> f32 {
    match path.extension().and_then(|e| e.to_str()) {
        Some("js" | "min.js" | "min.css") => base + 0.5,
        Some("env" | "config" | "properties" | "ini") => base - 0.3,
        Some("json" | "yaml" | "yml" | "toml") => base - 0.2,
        _ => base,
    }
}

struct ScanFileParams<'a> {
    entropy_threshold: f32,
    disabled_rules: &'a [String],
    whitelist: &'a [String],
    custom_rules: &'a [CompiledCustomRule],
    skip_minified: usize,
    skip_entropy_in_regex_context: bool,
    allowlist_regexes: Option<Arc<Vec<Regex>>>,
}

fn scan_file_text(
    file_path: &Path,
    path_str: &str,
    text: &str,
    params: &ScanFileParams<'_>,
    commit_hash: Option<&String>,
) -> Vec<Sin> {
    let lines: Vec<&str> = text.lines().collect();
    let ignore_ranges = compute_ignore_ranges(&lines);
    let mut file_sins = Vec::new();

    for (line_idx, line) in lines.iter().enumerate() {
        if ignore_ranges
            .iter()
            .any(|range| line_idx >= range.start && line_idx <= range.end)
        {
            continue;
        }
        if line.contains("velka:ignore") {
            continue;
        }
        if line.len() > params.skip_minified {
            continue;
        }

        let line_num = line_idx + 1;
        let line_context = build_context(&lines, line_idx);
        let adaptive_threshold = get_entropy_threshold(file_path, params.entropy_threshold);
        let scan_cfg = AnalyzeLineConfig {
            entropy_threshold: adaptive_threshold,
            disabled_rules: params.disabled_rules,
            whitelist: params.whitelist,
            custom_rules: params.custom_rules,
            skip_entropy_in_regex_context: params.skip_entropy_in_regex_context,
            allowlist_regexes: params.allowlist_regexes.as_ref().map(|v| v.as_slice()),
        };

        if let Some(sin) = analyze_line(
            line,
            path_str,
            line_num,
            line_context,
            commit_hash.cloned(),
            &scan_cfg,
        ) {
            file_sins.push(sin);
        }
    }

    file_sins
}

pub fn scan_content(content: &str, config: &VelkaConfig) -> Result<Vec<Sin>> {
    let custom_rules = config.compile_custom_rules()?;
    let custom_rules: Arc<Vec<CompiledCustomRule>> = Arc::new(custom_rules);
    let disabled_rules: Vec<String> = config.rules.disable.clone();
    let whitelist: Vec<String> = config.scan.whitelist.clone();
    let allowlist_regexes = compile_allowlist_regexes(config.scan.allowlist.as_ref())
        .ok()
        .map(Arc::new);
    let params = ScanFileParams {
        entropy_threshold: config.scan.entropy_threshold,
        disabled_rules: &disabled_rules,
        whitelist: &whitelist,
        custom_rules: &custom_rules,
        skip_minified: config.scan.skip_minified_threshold,
        skip_entropy_in_regex_context: config.scan.entropy_skip_regex_context,
        allowlist_regexes,
    };
    let path_str = "<stdin>";
    let dummy_path = Path::new("<stdin>");
    Ok(scan_file_text(dummy_path, path_str, content, &params, None))
}

pub fn investigate(path: &Path, config: &VelkaConfig, sender: &Sender<Sin>) -> Result<()> {
    investigate_with_progress(path, config, sender, false)
}

pub fn scan_single_file(
    file_path: &Path,
    config: &VelkaConfig,
    sender: &Sender<Sin>,
    cache: Option<&Arc<std::sync::RwLock<ScanCache>>>,
) -> Result<()> {
    let custom_rules = config.compile_custom_rules()?;
    let custom_rules: Arc<Vec<CompiledCustomRule>> = Arc::new(custom_rules);

    let mut ignore_paths: Vec<String> = config.scan.ignore_paths.clone();
    if let Some(ref allowlist) = config.scan.allowlist {
        ignore_paths.extend(allowlist.paths.clone());
    }
    let ignore_patterns: Vec<Pattern> = ignore_paths
        .iter()
        .filter_map(|p| Pattern::new(p).ok())
        .collect();

    let path_str = file_path.to_string_lossy();
    if ignore_patterns.iter().any(|pat| pat.matches(&path_str)) {
        return Ok(());
    }
    if let Some(ref allowlist) = config.scan.allowlist {
        if let Ok(file_patterns) = compile_allowlist_file_patterns(Some(allowlist)) {
            if file_patterns
                .iter()
                .any(|re| re.is_match(path_str.as_ref()))
            {
                return Ok(());
            }
        }
    }

    let disabled_rules: Vec<String> = config.rules.disable.clone();
    let whitelist: Vec<String> = config.scan.whitelist.clone();
    let entropy_threshold = config.scan.entropy_threshold;
    let max_file_size = config.scan.max_file_size_mb * 1_048_576;
    let skip_minified = config.scan.skip_minified_threshold;

    let Some(file_content) = read_file_content(file_path, max_file_size) else {
        return Ok(());
    };

    let content_ref = file_content.as_ref();
    let file_hash = ScanCache::hash_content(content_ref);

    if let Some(cache_rw) = cache {
        if let Ok(cache_guard) = cache_rw.read() {
            if let Some(cached_entry) = cache_guard.get(&path_str, &file_hash) {
                for cached_match in &cached_entry.rule_matches {
                    let severity = match cached_match.severity.as_str() {
                        "Mortal" => Severity::Mortal,
                        "Venial" => Severity::Venial,
                        _ => continue,
                    };

                    let sin = Sin {
                        path: path_str.to_string(),
                        line_number: cached_match.line_number,
                        snippet: String::new(),
                        context: Vec::new(),
                        severity,
                        description: format!("Cached: {}", cached_match.rule_id),
                        rule_id: cached_match.rule_id.clone(),
                        commit_hash: None,
                        verified: None,
                        confidence: None,
                        confidence_factors: None,
                    };

                    if sender.send(sin).is_err() {
                        return Ok(());
                    }
                }
                return Ok(());
            }
        }
    }

    if is_binary(content_ref) {
        return Ok(());
    }

    let Ok(text) = std::str::from_utf8(content_ref) else {
        return Ok(());
    };

    let allowlist_regexes = compile_allowlist_regexes(config.scan.allowlist.as_ref())
        .ok()
        .map(Arc::new);
    let params = ScanFileParams {
        entropy_threshold,
        disabled_rules: &disabled_rules,
        whitelist: &whitelist,
        custom_rules: &custom_rules,
        skip_minified,
        skip_entropy_in_regex_context: config.scan.entropy_skip_regex_context,
        allowlist_regexes,
    };
    let mut file_sins = scan_file_text(file_path, &path_str, text, &params, None);

    if config.scan.verify {
        for sin in &mut file_sins {
            verifier::verify(sin);
            compute_confidence(sin);
        }
    } else {
        for sin in &mut file_sins {
            compute_confidence(sin);
        }
    }

    if cache.is_some() {
        for sin in &file_sins {
            if sender.send(sin.clone()).is_err() {
                return Ok(());
            }
        }
    } else {
        for sin in file_sins {
            if sender.send(sin).is_err() {
                return Ok(());
            }
        }
        return Ok(());
    }

    if let Some(cache_rw) = cache {
        let cached_matches: Vec<CachedMatch> = file_sins
            .into_iter()
            .map(|sin| CachedMatch {
                line_number: sin.line_number,
                rule_id: sin.rule_id,
                severity: format!("{:?}", sin.severity),
            })
            .collect();

        let cache_entry = CacheEntry {
            file_hash,
            rule_matches: cached_matches,
            scanned_at: Utc::now().timestamp(),
        };

        if let Ok(mut cache_guard) = cache_rw.write() {
            cache_guard.insert(path_str.to_string(), cache_entry);
        }
    }

    Ok(())
}

pub fn investigate_with_progress(
    path: &Path,
    config: &VelkaConfig,
    sender: &Sender<Sin>,
    show_progress: bool,
) -> Result<()> {
    let custom_rules = config.compile_custom_rules()?;
    let custom_rules: Arc<Vec<CompiledCustomRule>> = Arc::new(custom_rules);

    let cache: Option<Arc<std::sync::RwLock<ScanCache>>> = if config.cache.enabled {
        Some(Arc::new(std::sync::RwLock::new(ScanCache::new(
            &config.cache.location,
            path,
        ))))
    } else {
        None
    };

    let mut ignore_paths: Vec<String> = config.scan.ignore_paths.clone();
    if let Some(ref allowlist) = config.scan.allowlist {
        ignore_paths.extend(allowlist.paths.clone());
    }
    let ignore_patterns: Arc<Vec<Pattern>> = Arc::new(
        ignore_paths
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect(),
    );
    let allowlist_file_patterns = compile_allowlist_file_patterns(config.scan.allowlist.as_ref())
        .ok()
        .map(Arc::new);
    let allowlist_regexes = compile_allowlist_regexes(config.scan.allowlist.as_ref())
        .ok()
        .map(Arc::new);

    let disabled_rules: Arc<Vec<String>> = Arc::new(config.rules.disable.clone());
    let whitelist: Arc<Vec<String>> = Arc::new(config.scan.whitelist.clone());
    let entropy_threshold = config.scan.entropy_threshold;
    let max_file_size = config.scan.max_file_size_mb * 1_048_576;
    let skip_minified = config.scan.skip_minified_threshold;
    let verify_secrets = config.scan.verify;

    let (pb, progress_step, total_files) = if show_progress {
        #[allow(clippy::redundant_closure_for_method_calls)]
        let file_count: u64 = ignore::WalkBuilder::new(path)
            .hidden(false)
            .git_ignore(true)
            .build()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .count() as u64;

        let step = std::cmp::max(1, file_count / 100);
        let progress_bar = ProgressBar::new(file_count);
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("█▓░"),
        );
        (Some(Arc::new(progress_bar)), step, file_count)
    } else {
        (None, 1_u64, 0_u64)
    };

    let cache_pending: Arc<Mutex<Vec<(String, CacheEntry)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let progress_counter = Arc::new(AtomicU64::new(0));

    let walker = ignore::WalkBuilder::new(path)
        .hidden(false)
        .git_ignore(true)
        .build_parallel();

    walker.run(|| {
        let tx = sender.clone();
        let patterns = Arc::clone(&ignore_patterns);
        let allowlist_file_patterns = allowlist_file_patterns.clone();
        let allowlist_regexes = allowlist_regexes.clone();
        let disabled = Arc::clone(&disabled_rules);
        let wl = Arc::clone(&whitelist);
        let custom = Arc::clone(&custom_rules);
        let cache_clone = cache.clone();
        let cache_pending_clone = Arc::clone(&cache_pending);
        let threshold = entropy_threshold;
        let max_size = max_file_size;
        let minified_limit = skip_minified;
        let pb_clone = pb.clone();
        let counter = Arc::clone(&progress_counter);
        let do_verify = verify_secrets;
        let step = progress_step;

        Box::new(move |entry_result| {
            let Ok(entry) = entry_result else {
                return ignore::WalkState::Continue;
            };

            let file_path = entry.path();
            if !file_path.is_file() {
                return ignore::WalkState::Continue;
            }

            if let Some(ref progress_bar) = pb_clone {
                let count = counter.fetch_add(1, Ordering::Relaxed);
                if count > 0 && count.is_multiple_of(step) {
                    progress_bar.set_position(count);
                }
            }

            let path_str = file_path.to_string_lossy();
            if patterns.iter().any(|pat| pat.matches(&path_str)) {
                return ignore::WalkState::Continue;
            }
            if let Some(ref file_patterns) = allowlist_file_patterns {
                if file_patterns.iter().any(|re| re.is_match(path_str.as_ref())) {
                    return ignore::WalkState::Continue;
                }
            }

            let Some(file_content) = read_file_content(file_path, max_size) else {
                return ignore::WalkState::Continue;
            };

            let content_ref = file_content.as_ref();
            let file_hash = ScanCache::hash_content(content_ref);

            if let Some(cache_rw) = cache_clone.as_ref() {
                if let Ok(cache_guard) = cache_rw.read() {
                    if let Some(cached_entry) = cache_guard.get(&path_str, &file_hash) {
                        for cached_match in &cached_entry.rule_matches {
                            let severity = match cached_match.severity.as_str() {
                                "Mortal" => Severity::Mortal,
                                "Venial" => Severity::Venial,
                                _ => continue,
                            };

                            let sin = Sin {
                                path: path_str.to_string(),
                                line_number: cached_match.line_number,
                                snippet: String::new(),
                                context: Vec::new(),
                                severity,
                                description: format!("Cached: {}", cached_match.rule_id),
                                rule_id: cached_match.rule_id.clone(),
                                commit_hash: None,
                                verified: None,
                                confidence: None,
                                confidence_factors: None,
                            };

                            if tx.send(sin).is_err() {
                                return ignore::WalkState::Quit;
                            }
                        }
                        return ignore::WalkState::Continue;
                    }
                }
            }

            if is_binary(content_ref) {
                return ignore::WalkState::Continue;
            }

            let Ok(text) = std::str::from_utf8(content_ref) else {
                return ignore::WalkState::Continue;
            };

            let params = ScanFileParams {
                entropy_threshold: threshold,
                disabled_rules: &disabled,
                whitelist: &wl,
                custom_rules: &custom,
                skip_minified: minified_limit,
                skip_entropy_in_regex_context: true,
                allowlist_regexes: allowlist_regexes.clone(),
            };
            let mut file_sins = scan_file_text(file_path, &path_str, text, &params, None);

            if do_verify {
                for sin in &mut file_sins {
                    verifier::verify(sin);
                    compute_confidence(sin);
                }
            } else {
                for sin in &mut file_sins {
                    compute_confidence(sin);
                }
            }

            if cache_clone.as_ref().is_some() {
                for sin in &file_sins {
                    if tx.send(sin.clone()).is_err() {
                        return ignore::WalkState::Quit;
                    }
                }
                let cached_matches: Vec<CachedMatch> = file_sins
                    .iter()
                    .map(|sin| CachedMatch {
                        line_number: sin.line_number,
                        rule_id: sin.rule_id.clone(),
                        severity: format!("{:?}", sin.severity),
                    })
                    .collect();
                let cache_entry = CacheEntry {
                    file_hash,
                    rule_matches: cached_matches,
                    scanned_at: Utc::now().timestamp(),
                };
                if let Ok(mut pending) = cache_pending_clone.lock() {
                    pending.push((path_str.to_string(), cache_entry));
                }
            } else {
                for sin in file_sins {
                    if tx.send(sin).is_err() {
                        return ignore::WalkState::Quit;
                    }
                }
            }

            ignore::WalkState::Continue
        })
    });

    if let Some(ref progress_bar) = pb {
        progress_bar.set_position(total_files);
        progress_bar.finish_with_message("Scan complete");
    }

    if let Some(cache_rw) = cache {
        let pending = cache_pending
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default();
        if !pending.is_empty() {
            if let Ok(mut cache_guard) = cache_rw.write() {
                cache_guard.insert_batch(pending);
            }
        }
        if let Ok(cache_guard) = cache_rw.write() {
            let _ = cache_guard.save();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;
    use std::fs;

    #[test]
    fn test_investigate_finds_secret() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("secret.rs");
        fs::write(&path, r#"let key = "AKIA0000000000000000";"#).unwrap();
        let config = crate::config::VelkaConfig::default();
        let (sender, receiver) = unbounded();
        scan_single_file(&path, &config, &sender, None).unwrap();
        drop(sender);
        let sins: Vec<Sin> = receiver.iter().collect();
        assert!(!sins.is_empty());
        assert!(sins.iter().any(|s| s.rule_id == "AWS_ACCESS_KEY"));
    }

    #[test]
    fn test_investigate_clean_dir_empty() {
        let config = crate::config::VelkaConfig::default();
        let result = scan_content("fn main() { let x = 1; }", &config);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_scan_single_file_finds_secret() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("key.rs");
        fs::write(
            &path,
            r#"const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";"#,
        )
        .unwrap();
        let config = crate::config::VelkaConfig::default();
        let (sender, receiver) = unbounded();
        scan_single_file(&path, &config, &sender, None).unwrap();
        drop(sender);
        let sins: Vec<Sin> = receiver.iter().collect();
        assert!(!sins.is_empty());
        assert!(sins.iter().any(|s| s.rule_id == "GITHUB_TOKEN"));
    }

    #[test]
    fn test_scan_single_file_ignore_pattern_skipped() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("secret.rs");
        fs::write(&path, r#"let key = "AKIA0000000000000000";"#).unwrap();
        let mut config = crate::config::VelkaConfig::default();
        config.scan.ignore_paths = vec!["**/secret.rs".to_string()];
        let (sender, receiver) = unbounded();
        scan_single_file(&path, &config, &sender, None).unwrap();
        drop(sender);
        let sins: Vec<Sin> = receiver.iter().collect();
        assert!(sins.is_empty());
    }
}
