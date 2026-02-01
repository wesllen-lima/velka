use std::path::Path;

use crate::error::Result;
use crossbeam_channel::Sender;

use crate::domain::Severity;
use crate::domain::Sin;
use crate::utils::build_context;

fn count_leading_spaces(line: &str) -> usize {
    line.chars()
        .take_while(|&c| c == ' ' || c == '\t')
        .map(|c| if c == '\t' { 4 } else { 1 })
        .sum()
}

fn is_function_start(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("fn ")
        || trimmed.starts_with("function ")
        || trimmed.starts_with("def ")
        || trimmed.starts_with("func ")
        || (trimmed.starts_with("pub fn ") || trimmed.starts_with("async fn "))
}

fn count_complexity_keywords(line: &str) -> usize {
    let line_lower = line.to_lowercase();
    let mut count = 0;

    if line_lower.contains(" if ") || line_lower.starts_with("if ") {
        count += 1;
    }
    if line_lower.contains(" else if ") || line_lower.contains(" elif ") {
        count += 1;
    }
    if line_lower.contains(" for ") || line_lower.starts_with("for ") {
        count += 1;
    }
    if line_lower.contains(" while ") || line_lower.starts_with("while ") {
        count += 1;
    }
    if line_lower.contains(" match ") || line_lower.starts_with("match ") {
        count += 1;
    }
    if line_lower.contains(" switch ") || line_lower.starts_with("switch ") {
        count += 1;
    }
    if line_lower.contains(" case ") || line_lower.starts_with("case ") {
        count += 1;
    }
    if line_lower.contains(" catch ") || line_lower.starts_with("catch ") {
        count += 1;
    }
    if line_lower.contains(" && ") || line_lower.contains(" || ") {
        count += 1;
    }

    count
}

fn context_to_vec(ctx: [&str; 3]) -> Vec<String> {
    ctx.iter().map(std::string::ToString::to_string).collect()
}

pub fn analyze_complexity(path: &Path, sender: &Sender<Sin>) -> Result<()> {
    let walker = ignore::WalkBuilder::new(path)
        .hidden(false)
        .git_ignore(true)
        .build_parallel();

    walker.run(|| {
        let tx = sender.clone();
        Box::new(move |entry_result| {
            let Ok(entry) = entry_result else {
                return ignore::WalkState::Continue;
            };

            let file_path = entry.path();
            if !file_path.is_file() {
                return ignore::WalkState::Continue;
            }

            let Ok(file_content) = std::fs::read(file_path) else {
                return ignore::WalkState::Continue;
            };

            if file_content.len() > 1024 * 1024 || file_content.contains(&0) {
                return ignore::WalkState::Continue;
            }

            let Ok(text) = String::from_utf8(file_content) else {
                return ignore::WalkState::Continue;
            };

            let lines: Vec<&str> = text.lines().collect();
            let path_str = file_path.to_string_lossy().to_string();

            let mut current_function_start: Option<usize> = None;
            let mut complexity_score = 0;
            let mut base_indent = 0;

            for (line_idx, line) in lines.iter().enumerate() {
                let line_num = line_idx + 1;
                let indent = count_leading_spaces(line);

                if is_function_start(line) {
                    if let Some(func_start) = current_function_start {
                        if complexity_score > 15 {
                            let line_context =
                                context_to_vec(build_context(&lines, func_start.saturating_sub(1)));
                            let sin = Sin {
                                path: path_str.clone(),
                                line_number: func_start,
                                snippet: lines[func_start - 1].trim().to_string(),
                                context: line_context,
                                severity: Severity::Venial,
                                description: format!(
                                    "Function complexity score {complexity_score} exceeds threshold (15)",
                                ),
                                rule_id: "COMPLEXITY_SIN".to_string(),
                                commit_hash: None,
                                verified: None,
                                confidence: None,
                                confidence_factors: None,
                            };

                            if tx.send(sin).is_err() {
                                return ignore::WalkState::Quit;
                            }
                        }
                    }

                    current_function_start = Some(line_num);
                    complexity_score = 0;
                    base_indent = indent;
                } else if current_function_start.is_some() {
                    let nested_level = if indent > base_indent {
                        (indent - base_indent) / 4
                    } else {
                        0
                    };

                    let keyword_count = count_complexity_keywords(line);
                    complexity_score += keyword_count * (1 + nested_level);
                }
            }

            if let Some(func_start) = current_function_start {
                if complexity_score > 15 {
                    let line_context =
                        context_to_vec(build_context(&lines, func_start.saturating_sub(1)));
                    let sin = Sin {
                        path: path_str.clone(),
                        line_number: func_start,
                        snippet: lines[func_start - 1].trim().to_string(),
                        context: line_context,
                        severity: Severity::Venial,
                        description: format!(
                            "Function complexity score {complexity_score} exceeds threshold (15)",
                        ),
                        rule_id: "COMPLEXITY_SIN".to_string(),
                        commit_hash: None,
                        verified: None,
                        confidence: None,
                        confidence_factors: None,
                    };

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
