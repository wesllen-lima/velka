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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_leading_spaces() {
        assert_eq!(count_leading_spaces("hello"), 0);
        assert_eq!(count_leading_spaces("    hello"), 4);
        assert_eq!(count_leading_spaces("\thello"), 4);
        assert_eq!(count_leading_spaces("  \thello"), 6);
    }

    #[test]
    fn test_is_function_start() {
        assert!(is_function_start("fn main() {"));
        assert!(is_function_start("pub fn foo() {"));
        assert!(is_function_start("async fn bar() {"));
        assert!(is_function_start("def my_func():"));
        assert!(is_function_start("function doStuff() {"));
        assert!(is_function_start("func Handler() {"));
        assert!(!is_function_start("let x = 42;"));
        assert!(!is_function_start("// fn comment"));
    }

    #[test]
    fn test_count_complexity_keywords() {
        assert_eq!(count_complexity_keywords("if x > 0 {"), 1);
        assert_eq!(count_complexity_keywords("} else if y < 0 {"), 2); // " if " + " else if "
        assert_eq!(count_complexity_keywords("for item in items {"), 1);
        assert_eq!(count_complexity_keywords("while running {"), 1);
        assert_eq!(count_complexity_keywords("match result {"), 1);
        assert_eq!(count_complexity_keywords("if a && b || c {"), 2); // if + &&/||
        assert_eq!(count_complexity_keywords("let x = 42;"), 0);
    }

    #[test]
    fn test_analyze_complexity_detects_complex_function() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("complex.rs");
        // Build a function with complexity > 15
        let mut code = String::from("fn complex_function() {\n");
        for i in 0..20 {
            code.push_str(&format!("    if x_{} > 0 {{\n", i));
            code.push_str(&format!("        for j in 0..{} {{\n", i));
            code.push_str("            println!(\"nested\");\n");
            code.push_str("        }\n");
            code.push_str("    }\n");
        }
        code.push_str("}\n");
        std::fs::write(&path, &code).unwrap();

        let (sender, receiver) = crossbeam_channel::unbounded();
        analyze_complexity(tmp.path(), &sender).unwrap();
        drop(sender);
        let sins: Vec<Sin> = receiver.iter().collect();
        assert!(!sins.is_empty(), "Should detect complex function");
        assert!(sins.iter().all(|s| s.rule_id == "COMPLEXITY_SIN"));
    }

    #[test]
    fn test_analyze_complexity_simple_function_clean() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("simple.rs");
        std::fs::write(
            &path,
            "fn simple() {\n    let x = 1;\n    println!(\"{}\", x);\n}\n",
        )
        .unwrap();

        let (sender, receiver) = crossbeam_channel::unbounded();
        analyze_complexity(tmp.path(), &sender).unwrap();
        drop(sender);
        let sins: Vec<Sin> = receiver.iter().collect();
        assert!(
            sins.is_empty(),
            "Simple function should not trigger complexity sin"
        );
    }
}
