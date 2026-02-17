//! CLI commands for baseline tracking.
//!
//! ```text
//! velka baseline save          # snapshot current findings
//! velka baseline diff          # compare with snapshot
//! velka baseline diff --exit-code   # exits 1 if new findings
//! velka baseline show          # display the saved snapshot
//! ```

use std::path::{Path, PathBuf};

use anyhow::Result;
use colored::Colorize;
use crossbeam_channel::unbounded;

use velka::domain::Sin;
use velka::engine::baseline;
use velka::engine::investigate;

fn scan_dir(scan_path: &Path) -> Result<Vec<Sin>> {
    let config = velka::config::VelkaConfig::load()?;
    let (sender, receiver) = unbounded::<Sin>();
    investigate(scan_path, &config, &sender)?;
    drop(sender);
    Ok(receiver.iter().collect())
}

// ── Save ───────────────────────────────────────────────────────────────────

pub fn run_baseline_save(scan_path: &Path, baseline_file: Option<&Path>) -> Result<()> {
    println!("Scanning {}…", scan_path.display());
    let sins = scan_dir(scan_path)?;
    let count = sins.len();
    baseline::save(&sins, baseline_file)?;

    let dest = baseline_file.map_or_else(baseline::default_baseline_path, PathBuf::from);

    println!(
        "{} Baseline saved: {} finding(s) → {}",
        "✓".green().bold(),
        count,
        dest.display()
    );
    Ok(())
}

// ── Diff ───────────────────────────────────────────────────────────────────

pub fn run_baseline_diff(
    scan_path: &Path,
    baseline_file: Option<&Path>,
    exit_code: bool,
) -> Result<()> {
    let saved = baseline::load(baseline_file)?;
    println!(
        "Baseline: {} finding(s) @ {}",
        saved.total_findings, saved.created_at
    );
    println!("Scanning {}…\n", scan_path.display());

    let current = scan_dir(scan_path)?;
    let result = baseline::diff(&current, &saved);

    if result.new_findings.is_empty() {
        println!("{} No new findings since baseline.", "✓".green().bold());
    } else {
        println!(
            "{} NEW FINDINGS ({}):",
            "⚠".yellow().bold(),
            result.new_findings.len()
        );
        for entry in &result.new_findings {
            println!(
                "  {} {}:{} [{}]",
                "+".red().bold(),
                entry.path,
                entry.line_number,
                entry.rule_id
            );
        }
        println!();
    }

    if !result.removed_findings.is_empty() {
        println!(
            "{} RESOLVED ({}):",
            "✓".green().bold(),
            result.removed_findings.len()
        );
        for entry in &result.removed_findings {
            println!(
                "  {} {}:{} [{}]",
                "-".green().bold(),
                entry.path,
                entry.line_number,
                entry.rule_id
            );
        }
        println!();
    }

    println!(
        "Unchanged: {}  |  New: {}  |  Resolved: {}",
        result.unchanged_count,
        result.new_findings.len(),
        result.removed_findings.len()
    );

    if exit_code && result.has_regressions() {
        std::process::exit(1);
    }

    Ok(())
}

// ── Show ───────────────────────────────────────────────────────────────────

pub fn run_baseline_show(baseline_file: Option<&Path>) -> Result<()> {
    let saved = baseline::load(baseline_file)?;

    println!(
        "Baseline v{}  •  {}  •  {} finding(s)",
        saved.version, saved.created_at, saved.total_findings
    );

    if saved.entries.is_empty() {
        println!("(no findings)");
        return Ok(());
    }

    println!("\n{:<50} {:<6} {:<30}", "File", "Line", "Rule");
    println!("{}", "─".repeat(88));

    let mut entries = saved.entries.clone();
    entries.sort_by(|a, b| a.path.cmp(&b.path).then(a.line_number.cmp(&b.line_number)));

    for entry in &entries {
        println!(
            "{:<50} {:<6} {:<30}",
            &entry.path, entry.line_number, entry.rule_id
        );
    }

    Ok(())
}
