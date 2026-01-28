use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use crossbeam_channel::unbounded;

use velka::config::VelkaConfig;
use velka::domain::Severity;
use velka::domain::Sin;
use velka::engine::analyze_complexity;
use velka::engine::investigate;
use velka::engine::scan_history;
use velka::output::format_output;
use velka::output::OutputFormat;

#[derive(Parser)]
#[command(name = "velka", about = "The Code Sin Judge")]
enum Cli {
    Scan(ScanArgs),
    InstallHook,
}

#[derive(Parser)]
struct ScanArgs {
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(long, short, default_value = "terminal")]
    format: OutputFormat,

    #[arg(long, short, help = "Only report mortal sins")]
    mortal_only: bool,

    #[arg(long, help = "Scan git history for buried secrets")]
    deep_scan: bool,

    #[arg(long, help = "Enable complexity analysis")]
    complexity: bool,
}

fn main() -> Result<()> {
    match Cli::parse() {
        Cli::Scan(args) => {
            let config = VelkaConfig::load()?;

            let (sender, receiver) = unbounded::<Sin>();

            let path = args.path.clone();
            let config_clone = config.clone();
            let sender1 = sender.clone();
            std::thread::spawn(move || {
                if let Err(e) = investigate(&path, &config_clone, sender1) {
                    eprintln!("Error during investigation: {e}");
                }
            });

            if args.deep_scan {
                let path_git = args.path.clone();
                let sender2 = sender.clone();
                std::thread::spawn(move || {
                    if let Err(e) = scan_history(&path_git, sender2) {
                        eprintln!("Error during git history scan: {e}");
                    }
                });
            }

            if args.complexity {
                let path_comp = args.path.clone();
                let sender3 = sender.clone();
                std::thread::spawn(move || {
                    if let Err(e) = analyze_complexity(&path_comp, sender3) {
                        eprintln!("Error during complexity analysis: {e}");
                    }
                });
            }

            drop(sender);

            let mut sins = Vec::new();
            while let Ok(sin) = receiver.recv() {
                if args.mortal_only && sin.severity == Severity::Venial {
                    continue;
                }
                sins.push(sin);
            }

            let output = format_output(sins, args.format);
            print!("{output}");
        }
        Cli::InstallHook => {
            install_pre_commit_hook()?;
        }
    }

    Ok(())
}

fn install_pre_commit_hook() -> Result<()> {
    use std::fs;
    use std::path::PathBuf;

    let git_dir = PathBuf::from(".git");
    if !git_dir.exists() {
        anyhow::bail!("Not a git repository (.git directory not found)");
    }

    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)?;

    let hook_path = hooks_dir.join("pre-commit");
    let hook_content = r#"#!/bin/sh
# Installed by Velka
# Stops commit if Mortal Sins are found
velka scan . --mortal-only
if [ $? -ne 0 ]; then
    exit 1
fi
"#;

    fs::write(&hook_path, hook_content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }

    println!("Pre-commit hook installed successfully at {}", hook_path.display());
    Ok(())
}
