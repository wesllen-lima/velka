use std::io::Write;
use std::path::Path;

use anyhow::Result;
use crossbeam_channel::unbounded;

use velka::config::VelkaConfig;
use velka::domain::Sin;
use velka::engine::{scan_single_file, FeedbackStore};

pub fn run_feedback_mark(file: &Path, line: usize) -> Result<()> {
    let file = file.canonicalize()?;
    let config = VelkaConfig::load()?;
    let (sender, receiver) = unbounded::<Sin>();

    scan_single_file(&file, &config, &sender, None)?;
    drop(sender);

    let sins: Vec<Sin> = receiver.iter().collect();
    let target = sins.iter().find(|s| s.line_number == line);

    let Some(sin) = target else {
        println!("No finding at {}:{line}. Nothing to mark.", file.display());
        return Ok(());
    };

    println!(
        "Found: [{}] {} (line {})",
        sin.rule_id, sin.description, sin.line_number
    );
    println!("Snippet: {}", sin.snippet);
    print!("\nIs this a false positive? [y/N] ");
    std::io::stdout().flush()?;

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;

    if answer.trim().eq_ignore_ascii_case("y") {
        let mut store = FeedbackStore::load()?;
        store.mark_false_positive(sin)?;
        println!("Marked as false positive. It will be skipped in future scans.");
    } else {
        println!("Not marked. No changes made.");
    }

    Ok(())
}

pub fn run_feedback_list() -> Result<()> {
    let store = FeedbackStore::load()?;
    let entries = store.entries();

    if entries.is_empty() {
        println!("No feedback entries. All clear.");
        return Ok(());
    }

    println!("False positives ({}):", entries.len());
    println!("{:<25} {:<12} {:<20}", "Rule", "Pattern", "Created");
    println!("{}", "-".repeat(60));

    for entry in entries {
        println!(
            "{:<25} {:<12} {:<20}",
            entry.rule_id, entry.file_pattern, entry.created_at
        );
    }

    Ok(())
}

pub fn run_feedback_clear() -> Result<()> {
    let mut store = FeedbackStore::load()?;

    if store.entries().is_empty() {
        println!("No feedback entries to clear.");
        return Ok(());
    }

    let count = store.entries().len();
    store.clear()?;
    println!("Cleared {count} feedback entries.");

    Ok(())
}
