use colored::Colorize;
use serde::Serialize;

use crate::domain::Severity;
use crate::domain::Sin;
use crate::engine::RULES;
use crate::utils::calculate_entropy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terminal" | "term" | "tty" => Ok(Self::Terminal),
            "json" => Ok(Self::Json),
            _ => Err(format!("Unknown format: {s}")),
        }
    }
}

#[derive(Serialize)]
struct JsonOutput {
    sins: Vec<Sin>,
    summary: Summary,
}

#[derive(Serialize)]
struct Summary {
    mortal: usize,
    venial: usize,
}

pub fn format_output(sins: Vec<Sin>, format: OutputFormat) -> String {
    match format {
        OutputFormat::Terminal => format_terminal(sins),
        OutputFormat::Json => format_json(sins),
    }
}

fn format_terminal(sins: Vec<Sin>) -> String {
    let mut output = String::new();

    output.push_str(&format!(
        "{}\n",
        "┌─────────────────────────────────────────────────────────"
            .red()
            .bold()
    ));
    output.push_str(&format!(
        "{}\n",
        "│ THE BOOK OF THE GUILTY IS OPEN...".red().bold()
    ));
    output.push_str(&format!(
        "{}\n\n",
        "└─────────────────────────────────────────────────────────"
            .red()
            .bold()
    ));

    if sins.is_empty() {
        output.push_str(&format!(
            "{}\n",
            "Praise the Sun. No sins found.".green().bold()
        ));
        return output;
    }

    let mut current_file: Option<String> = None;
    let mut mortal_count = 0;
    let mut venial_count = 0;

    for sin in &sins {
        match sin.severity {
            Severity::Mortal => mortal_count += 1,
            Severity::Venial => venial_count += 1,
        }

        if current_file.as_ref() != Some(&sin.path) {
            current_file = Some(sin.path.clone());
            output.push_str(&format!("\n▸ {}\n", sin.path.bright_cyan().bold()));
        }

        let severity_label = match sin.severity {
            Severity::Mortal => "MORTAL".red().bold(),
            Severity::Venial => "VENIAL".yellow().bold(),
        };

        output.push_str(&format!(
            "  [LINE {}] {} - {}\n",
            sin.line_number.to_string().bright_white(),
            severity_label,
            sin.description.bright_white()
        ));

        if let Some(ref hash) = sin.commit_hash {
            output.push_str(&format!(
                "  {} Commit: {} (buried in history)\n",
                "⚰".bright_black(),
                hash.bright_black()
            ));
        }

        if sin.context.len() >= 3 {
            let prev = &sin.context[0];
            let curr = &sin.context[1];
            let next = &sin.context[2];

            let prev_num = sin.line_number.saturating_sub(1);
            let next_num = sin.line_number + 1;

            if !prev.is_empty() {
                output.push_str(&format!(
                    "    {} │ {}\n",
                    prev_num.to_string().dimmed(),
                    prev.dimmed()
                ));
            }

            let highlighted = highlight_secret(curr, &sin.rule_id);
            output.push_str(&format!(
                "    {} │ {}\n",
                sin.line_number.to_string().bright_red().bold(),
                highlighted
            ));

            if !next.is_empty() {
                output.push_str(&format!(
                    "    {} │ {}\n",
                    next_num.to_string().dimmed(),
                    next.dimmed()
                ));
            }
        }

        output.push('\n');
    }

    output.push_str(&format!(
        "{}\n",
        "═══════════════════════════════════════════════════════════".bright_black()
    ));

    let verdict = if mortal_count > 0 || venial_count > 0 {
        let mut parts = Vec::new();
        if mortal_count > 0 {
            parts.push(format!(
                "{} Mortal Sin{}",
                mortal_count,
                if mortal_count == 1 { "" } else { "s" }
            ));
        }
        if venial_count > 0 {
            parts.push(format!(
                "{} Venial Sin{}",
                venial_count,
                if venial_count == 1 { "" } else { "s" }
            ));
        }
        format!("VERDICT: {} condemned.", parts.join(", "))
    } else {
        "VERDICT: No sins found.".to_string()
    };

    output.push_str(&format!("{}\n", verdict.red().bold()));

    output
}

fn highlight_secret(line: &str, rule_id: &str) -> String {
    if rule_id == "HIGH_ENTROPY" {
        let quoted_strings = extract_quoted_strings(line);
        let mut result = line.to_string();
        for string in quoted_strings {
            if calculate_entropy(&string) > 4.5 {
                result = result.replace(&string, &string.red().bold().to_string());
            }
        }
        result
    } else {
        for rule in RULES {
            if rule.id == rule_id {
                if let Some(mat) = rule.pattern.find(line) {
                    let matched = mat.as_str();
                    return line.replace(matched, &matched.red().bold().to_string());
                }
            }
        }
        line.to_string()
    }
}

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

fn format_json(sins: Vec<Sin>) -> String {
    let mortal_count = sins
        .iter()
        .filter(|s| matches!(s.severity, Severity::Mortal))
        .count();
    let venial_count = sins
        .iter()
        .filter(|s| matches!(s.severity, Severity::Venial))
        .count();

    let output = JsonOutput {
        sins,
        summary: Summary {
            mortal: mortal_count,
            venial: venial_count,
        },
    };

    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
}
