use std::fmt::Write;

use colored::Colorize;
use serde::Serialize;

use crate::domain::Severity;
use crate::domain::Sin;
use crate::engine::RULES;
use crate::output::redact::{redact_line, RedactionConfig};
use crate::utils::{calculate_entropy, extract_quoted_string_contents};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    Json,
    Csv,
    Junit,
    Sarif,
    Markdown,
    Html,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terminal" | "term" | "tty" => Ok(Self::Terminal),
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            "junit" | "xml" => Ok(Self::Junit),
            "sarif" => Ok(Self::Sarif),
            "markdown" | "md" => Ok(Self::Markdown),
            "html" => Ok(Self::Html),
            _ => Err(format!("Unknown format: {s}. Valid options: terminal, json, csv, junit, sarif, markdown, html")),
        }
    }
}

#[derive(Serialize)]
struct JsonOutput {
    sins: Vec<RedactedSin>,
    summary: Summary,
}

#[derive(Serialize)]
struct RedactedSin {
    path: String,
    line_number: usize,
    snippet: String,
    severity: Severity,
    description: String,
    rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    commit_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
}

#[derive(Serialize)]
struct Summary {
    mortal: usize,
    venial: usize,
}

#[must_use]
pub fn format_output(
    sins: Vec<Sin>,
    format: OutputFormat,
    redaction: &RedactionConfig,
    ci_mode: bool,
) -> String {
    match format {
        OutputFormat::Terminal => format_terminal(&sins, redaction),
        OutputFormat::Json => format_json(sins, redaction),
        OutputFormat::Csv => format_csv(&sins, redaction),
        OutputFormat::Junit => format_junit(&sins, redaction),
        OutputFormat::Sarif => format_sarif(&sins, redaction),
        OutputFormat::Markdown => format_markdown(&sins, redaction, ci_mode),
        OutputFormat::Html => format_html(&sins, redaction, ci_mode),
    }
}

fn format_terminal(sins: &[Sin], redaction: &RedactionConfig) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "{}",
        "┌─────────────────────────────────────────────────────────"
            .red()
            .bold()
    );
    let _ = writeln!(
        output,
        "{}",
        "│ THE BOOK OF THE GUILTY IS OPEN...".red().bold()
    );
    let _ = writeln!(
        output,
        "{}\n",
        "└─────────────────────────────────────────────────────────"
            .red()
            .bold()
    );

    if sins.is_empty() {
        let _ = writeln!(
            output,
            "{}",
            "Praise the Sun. No sins found.".green().bold()
        );
        return output;
    }

    let mut current_file: Option<String> = None;
    let mut mortal_count = 0;
    let mut venial_count = 0;

    for sin in sins {
        match sin.severity {
            Severity::Mortal => mortal_count += 1,
            Severity::Venial => venial_count += 1,
        }

        if current_file.as_ref() != Some(&sin.path) {
            current_file = Some(sin.path.clone());
            let _ = writeln!(output, "\n▸ {}", sin.path.bright_cyan().bold());
        }

        let severity_label = match sin.severity {
            Severity::Mortal => "MORTAL".red().bold(),
            Severity::Venial => "VENIAL".yellow().bold(),
        };

        let _ = writeln!(
            output,
            "  [LINE {}] {} - {}",
            sin.line_number.to_string().bright_white(),
            severity_label,
            sin.description.bright_white()
        );

        if let Some(ref hash) = sin.commit_hash {
            let _ = writeln!(
                output,
                "  {} Commit: {} (buried in history)",
                "⚰".bright_black(),
                hash.as_str().bright_black()
            );
        }

        if sin.context.len() >= 3 {
            let prev = &sin.context[0];
            let curr = &sin.context[1];
            let next = &sin.context[2];

            let prev_num = sin.line_number.saturating_sub(1);
            let next_num = sin.line_number + 1;

            if !prev.is_empty() {
                let prev_redacted = redact_line(prev, &sin.rule_id, redaction);
                let _ = writeln!(
                    output,
                    "    {} │ {}",
                    prev_num.to_string().dimmed(),
                    prev_redacted.dimmed()
                );
            }

            let curr_redacted = redact_line(curr, &sin.rule_id, redaction);
            let highlighted = highlight_redacted(&curr_redacted, &sin.rule_id);
            let _ = writeln!(
                output,
                "    {} │ {}",
                sin.line_number.to_string().bright_red().bold(),
                highlighted
            );

            if !next.is_empty() {
                let next_redacted = redact_line(next, &sin.rule_id, redaction);
                let _ = writeln!(
                    output,
                    "    {} │ {}",
                    next_num.to_string().dimmed(),
                    next_redacted.dimmed()
                );
            }
        }

        output.push('\n');
    }

    let _ = writeln!(
        output,
        "{}",
        "═══════════════════════════════════════════════════════════".bright_black()
    );

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

    let _ = writeln!(output, "{}", verdict.red().bold());

    output
}

fn highlight_redacted(line: &str, rule_id: &str) -> String {
    if rule_id == "HIGH_ENTROPY" {
        if line.contains("****") {
            return line
                .split("****")
                .collect::<Vec<_>>()
                .join(&"****".red().bold().to_string());
        }
        let mut result = line.to_string();
        for string in extract_quoted_string_contents(line) {
            if calculate_entropy(string) > 4.5 {
                result = result.replace(string, &string.red().bold().to_string());
            }
        }
        result
    } else if line.contains("****") {
        line.split("****")
            .collect::<Vec<_>>()
            .join(&"****".red().bold().to_string())
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

fn format_json(sins: Vec<Sin>, redaction: &RedactionConfig) -> String {
    let redacted_sins: Vec<RedactedSin> = sins
        .into_iter()
        .map(|sin| {
            let snippet = redact_line(&sin.snippet, &sin.rule_id, redaction);
            RedactedSin {
                path: sin.path,
                line_number: sin.line_number,
                snippet,
                severity: sin.severity,
                description: sin.description,
                rule_id: sin.rule_id,
                commit_hash: sin.commit_hash,
                verified: sin.verified,
            }
        })
        .collect();

    let mortal_count = redacted_sins
        .iter()
        .filter(|s| matches!(s.severity, Severity::Mortal))
        .count();
    let venial_count = redacted_sins
        .iter()
        .filter(|s| matches!(s.severity, Severity::Venial))
        .count();

    let output = JsonOutput {
        sins: redacted_sins,
        summary: Summary {
            mortal: mortal_count,
            venial: venial_count,
        },
    };

    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
}

fn format_csv(sins: &[Sin], redaction: &RedactionConfig) -> String {
    let mut wtr = csv::Writer::from_writer(vec![]);

    if wtr
        .write_record(["Path", "Line", "Severity", "Rule", "Description", "Snippet"])
        .is_err()
    {
        return String::new();
    }

    for sin in sins {
        let snippet = redact_line(&sin.snippet, &sin.rule_id, redaction);
        let severity = match sin.severity {
            Severity::Mortal => "Mortal",
            Severity::Venial => "Venial",
        };
        if wtr
            .write_record([
                &sin.path,
                &sin.line_number.to_string(),
                severity,
                &sin.rule_id,
                &sin.description,
                &snippet,
            ])
            .is_err()
        {}
    }

    wtr.into_inner()
        .ok()
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_default()
}

fn format_junit(sins: &[Sin], redaction: &RedactionConfig) -> String {
    let mortal_count = sins
        .iter()
        .filter(|s| matches!(s.severity, Severity::Mortal))
        .count();

    let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    xml.push('\n');
    let _ = write!(
        xml,
        r#"<testsuite name="velka" tests="{}" failures="{}" errors="0">"#,
        sins.len(),
        mortal_count
    );
    xml.push('\n');

    for sin in sins {
        let snippet = redact_line(&sin.snippet, &sin.rule_id, redaction);
        let escaped_path = escape_xml(&sin.path);
        let escaped_desc = escape_xml(&sin.description);
        let escaped_snippet = escape_xml(&snippet);

        let _ = write!(
            xml,
            r#"  <testcase name="{}" classname="{}">"#,
            sin.rule_id, escaped_path
        );
        xml.push('\n');

        if matches!(sin.severity, Severity::Mortal) {
            let _ = write!(
                xml,
                r#"    <failure message="{}">Line {}: {}</failure>"#,
                escaped_desc, sin.line_number, escaped_snippet
            );
            xml.push('\n');
        }

        xml.push_str("  </testcase>\n");
    }

    xml.push_str("</testsuite>\n");
    xml
}

fn format_sarif(sins: &[Sin], redaction: &RedactionConfig) -> String {
    let results: Vec<serde_json::Value> = sins
        .iter()
        .map(|sin| {
            let snippet = redact_line(&sin.snippet, &sin.rule_id, redaction);
            let level = match sin.severity {
                Severity::Mortal => "error",
                Severity::Venial => "warning",
            };
            serde_json::json!({
                "ruleId": sin.rule_id,
                "level": level,
                "message": {
                    "text": sin.description
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": sin.path
                        },
                        "region": {
                            "startLine": sin.line_number,
                            "snippet": {
                                "text": snippet
                            }
                        }
                    }
                }]
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "velka",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/wesllen-lima/velka"
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

fn format_markdown(sins: &[Sin], redaction: &RedactionConfig, ci_mode: bool) -> String {
    let mut md = String::from("# Velka Security Report\n\n");

    let mortal_count = sins
        .iter()
        .filter(|s| matches!(s.severity, Severity::Mortal))
        .count();
    let venial_count = sins.len() - mortal_count;

    let _ = writeln!(
        md,
        "**Summary:** {mortal_count} Mortal, {venial_count} Venial sins found\n"
    );

    if sins.is_empty() {
        md.push_str("No security issues found.\n");
        return md;
    }

    md.push_str("| Severity | File | Line | Rule | Description |\n");
    md.push_str("|----------|------|------|------|-------------|\n");

    for sin in sins {
        let severity_badge = if ci_mode {
            match sin.severity {
                Severity::Mortal => "[MORTAL]",
                Severity::Venial => "[VENIAL]",
            }
        } else {
            match sin.severity {
                Severity::Mortal => "🔴 Mortal",
                Severity::Venial => "🟡 Venial",
            }
        };
        let _snippet = redact_line(&sin.snippet, &sin.rule_id, redaction);
        let _ = writeln!(
            md,
            "| {severity_badge} | `{}` | {} | {} | {} |",
            sin.path, sin.line_number, sin.rule_id, sin.description
        );
    }

    md
}

fn format_html(sins: &[Sin], redaction: &RedactionConfig, _ci_mode: bool) -> String {
    let mortal_count = sins
        .iter()
        .filter(|s| matches!(s.severity, Severity::Mortal))
        .count();
    let venial_count = sins.len() - mortal_count;

    let mut html = String::from(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Velka Security Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2rem; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; }
        .summary { background: #16213e; padding: 1rem; border-radius: 8px; margin-bottom: 2rem; }
        .mortal { color: #e94560; font-weight: bold; }
        .venial { color: #f39c12; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; background: #16213e; border-radius: 8px; overflow: hidden; }
        th { background: #0f3460; padding: 1rem; text-align: left; }
        td { padding: 1rem; border-top: 1px solid #0f3460; }
        tr:hover { background: #1a1a3e; }
        code { background: #0f3460; padding: 0.2rem 0.5rem; border-radius: 4px; font-family: 'Fira Code', monospace; }
        .badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.875rem; }
        .badge-mortal { background: #e94560; }
        .badge-venial { background: #f39c12; color: #1a1a2e; }
    </style>
</head>
<body>
    <h1>Velka Security Report</h1>
    <div class="summary">
"#,
    );

    let _ = write!(
        html,
        r#"        <p><span class="mortal">{mortal_count}</span> Mortal Sins | <span class="venial">{venial_count}</span> Venial Sins</p>
    </div>
"#
    );

    if sins.is_empty() {
        html.push_str("    <p>No security issues found.</p>\n");
    } else {
        html.push_str(
            r"    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>File</th>
                <th>Line</th>
                <th>Rule</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody>
",
        );

        for sin in sins {
            let (badge_class, badge_text) = match sin.severity {
                Severity::Mortal => ("badge-mortal", "Mortal"),
                Severity::Venial => ("badge-venial", "Venial"),
            };
            let _snippet = redact_line(&sin.snippet, &sin.rule_id, redaction);
            let escaped_path = escape_xml(&sin.path);
            let escaped_desc = escape_xml(&sin.description);

            let _ = write!(
                html,
                r#"            <tr>
                <td><span class="badge {badge_class}">{badge_text}</span></td>
                <td><code>{escaped_path}</code></td>
                <td>{}</td>
                <td>{}</td>
                <td>{escaped_desc}</td>
            </tr>
"#,
                sin.line_number, sin.rule_id
            );
        }

        html.push_str(
            r"        </tbody>
    </table>
",
        );
    }

    html.push_str(
        r"</body>
</html>
",
    );

    html
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sin() -> Sin {
        Sin {
            path: "test.rs".to_string(),
            line_number: 42,
            snippet: r#"let key = "AKIAIOSFODNN7EXAMPLE";"#.to_string(),
            context: vec![
                String::new(),
                r#"let key = "AKIAIOSFODNN7EXAMPLE";"#.to_string(),
                String::new(),
            ],
            severity: Severity::Mortal,
            description: "AWS Access Key ID detected".to_string(),
            rule_id: "AWS_ACCESS_KEY".to_string(),
            commit_hash: None,
            verified: None,
        }
    }

    #[test]
    fn test_format_json() {
        let sins = vec![sample_sin()];
        let redaction = RedactionConfig {
            enabled: true,
            visible_chars: 4,
        };
        let output = format_output(sins, OutputFormat::Json, &redaction, false);
        assert!(output.contains("\"sins\""));
        assert!(output.contains("\"summary\""));
        assert!(output.contains("AWS_ACCESS_KEY"));
    }

    #[test]
    fn test_format_csv() {
        let sins = vec![sample_sin()];
        let redaction = RedactionConfig {
            enabled: true,
            visible_chars: 4,
        };
        let output = format_output(sins, OutputFormat::Csv, &redaction, false);
        assert!(output.contains("Path,Line,Severity"));
        assert!(output.contains("test.rs"));
        assert!(output.contains("AWS_ACCESS_KEY"));
    }

    #[test]
    fn test_format_junit() {
        let sins = vec![sample_sin()];
        let redaction = RedactionConfig {
            enabled: true,
            visible_chars: 4,
        };
        let output = format_output(sins, OutputFormat::Junit, &redaction, false);
        assert!(output.contains("<testsuite"));
        assert!(output.contains("test.rs"));
        assert!(output.contains("AWS_ACCESS_KEY"));
    }

    #[test]
    fn test_format_sarif() {
        let sins = vec![sample_sin()];
        let redaction = RedactionConfig {
            enabled: true,
            visible_chars: 4,
        };
        let output = format_output(sins, OutputFormat::Sarif, &redaction, false);
        assert!(output.contains("\"$schema\""));
        assert!(output.contains("\"version\""));
        assert!(output.contains("test.rs"));
    }

    #[test]
    fn test_format_markdown() {
        let sins = vec![sample_sin()];
        let redaction = RedactionConfig {
            enabled: true,
            visible_chars: 4,
        };
        let output = format_output(sins, OutputFormat::Markdown, &redaction, false);
        assert!(output.contains("# Velka Security Report"));
        assert!(output.contains("test.rs"));
        assert!(output.contains("AWS_ACCESS_KEY"));
    }

    #[test]
    fn test_format_html() {
        let sins = vec![sample_sin()];
        let redaction = RedactionConfig {
            enabled: true,
            visible_chars: 4,
        };
        let output = format_output(sins, OutputFormat::Html, &redaction, false);
        assert!(output.contains("<html"));
        assert!(output.contains("<table"));
        assert!(output.contains("test.rs"));
    }

    #[test]
    fn test_format_empty() {
        let sins = vec![];
        let redaction = RedactionConfig {
            enabled: true,
            visible_chars: 4,
        };
        let json_output = format_output(sins.clone(), OutputFormat::Json, &redaction, false);
        assert!(json_output.contains("\"sins\": []"));

        let terminal_output = format_output(sins, OutputFormat::Terminal, &redaction, false);
        assert!(terminal_output.contains("No sins found"));
    }
}
