use std::path::Path;

use anyhow::Result;
use crossbeam_channel::Sender;
use glob::Pattern;

use crate::config::VelkaConfig;
use crate::domain::Severity;
use crate::domain::Sin;
use crate::engine::RULES;
use crate::utils::calculate_entropy;

fn extract_quoted_strings(line: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let mut in_double = false;
    let mut in_single = false;
    let mut start = 0;

    for (i, ch) in line.char_indices() {
        match ch {
            '"' if !in_single => {
                if in_double {
                    let s = &line[start + 1..i];
                    if s.len() > 20 {
                        strings.push(s.to_string());
                    }
                    in_double = false;
                } else {
                    in_double = true;
                    start = i;
                }
            }
            '\'' if !in_double => {
                if in_single {
                    let s = &line[start + 1..i];
                    if s.len() > 20 {
                        strings.push(s.to_string());
                    }
                    in_single = false;
                } else {
                    in_single = true;
                    start = i;
                }
            }
            _ => {}
        }
    }

    strings
}

fn is_likely_binary(content: &[u8]) -> bool {
    content.len() > 1024 * 1024
        || content.contains(&0)
        || content
            .iter()
            .filter(|&&b| b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D)
            .count()
            > content.len() / 4
}

fn build_context(lines: &[&str], line_idx: usize) -> Vec<String> {
    let mut context = Vec::with_capacity(3);

    if line_idx > 0 {
        context.push(lines[line_idx - 1].to_string());
    } else {
        context.push(String::new());
    }

    context.push(lines[line_idx].to_string());

    if line_idx + 1 < lines.len() {
        context.push(lines[line_idx + 1].to_string());
    } else {
        context.push(String::new());
    }

    context
}

pub fn analyze_line(
    line: &str,
    path_str: &str,
    line_num: usize,
    context: Vec<String>,
    commit_hash: Option<String>,
    entropy_threshold: f32,
    disabled_rules: &[String],
) -> Option<Sin> {
    for rule in RULES {
        if disabled_rules.contains(&rule.id.to_string()) {
            continue;
        }

        if rule.pattern.is_match(line) {
            if rule.id == "CREDIT_CARD" {
                if let Some(mat) = rule.pattern.find(line) {
                    let matched = mat.as_str();
                    if !crate::utils::luhn_is_valid(matched) {
                        continue;
                    }
                }
            }

            return Some(Sin {
                path: path_str.to_string(),
                line_number: line_num,
                snippet: line.trim().to_string(),
                context,
                severity: rule.severity,
                description: rule.description.to_string(),
                rule_id: rule.id.to_string(),
                commit_hash,
            });
        }
    }

    let quoted_strings = extract_quoted_strings(line);
    for string in quoted_strings {
        let entropy = calculate_entropy(&string);
        if entropy > entropy_threshold {
            return Some(Sin {
                path: path_str.to_string(),
                line_number: line_num,
                snippet: line.trim().to_string(),
                context,
                severity: Severity::Mortal,
                description: "High entropy string detected (potential secret)".to_string(),
                rule_id: "HIGH_ENTROPY".to_string(),
                commit_hash,
            });
        }
    }

    None
}

pub fn investigate(path: &Path, config: &VelkaConfig, sender: Sender<Sin>) -> Result<()> {
    let ignore_patterns: Vec<Pattern> = config
        .scan
        .ignore_paths
        .iter()
        .filter_map(|p| Pattern::new(p).ok())
        .collect();

    let disabled_rules = config.rules.disable.clone();
    let entropy_threshold = config.scan.entropy_threshold;

    let walker = ignore::WalkBuilder::new(path)
        .hidden(false)
        .git_ignore(true)
        .build_parallel();

    walker.run(|| {
        let tx = sender.clone();
        let patterns = ignore_patterns.clone();
        let disabled = disabled_rules.clone();
        let threshold = entropy_threshold;
        Box::new(move |entry_result| {
            let entry = match entry_result {
                Ok(e) => e,
                Err(_) => return ignore::WalkState::Continue,
            };

            let file_path = entry.path();
            if !file_path.is_file() {
                return ignore::WalkState::Continue;
            }

            let path_str = file_path.to_string_lossy();
            if patterns.iter().any(|pat| pat.matches(&path_str)) {
                return ignore::WalkState::Continue;
            }

            let content = match std::fs::read(file_path) {
                Ok(c) => c,
                Err(_) => return ignore::WalkState::Continue,
            };

            if is_likely_binary(&content) {
                return ignore::WalkState::Continue;
            }

            let text = match String::from_utf8(content) {
                Ok(t) => t,
                Err(_) => return ignore::WalkState::Continue,
            };

            let lines: Vec<&str> = text.lines().collect();

            for (line_idx, line) in lines.iter().enumerate() {
                if line.contains("velka:ignore") {
                    continue;
                }

                let line_num = line_idx + 1;
                let context = build_context(&lines, line_idx);

                if let Some(sin) = analyze_line(
                    line,
                    &path_str,
                    line_num,
                    context,
                    None,
                    threshold,
                    &disabled,
                ) {
                    if tx.send(sin).is_err() {
                        return ignore::WalkState::Quit;
                    }
                }
            }

            ignore::WalkState::Continue
        })
    });

    Ok(())
}
