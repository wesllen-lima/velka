use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::unbounded;

use velka::config::VelkaConfig;
use velka::domain::Severity;
use velka::domain::Sin;
use velka::engine::{
    analyze_complexity, format_migrate_report, get_changed_files, get_staged_files,
    investigate_with_progress, run_migrate, scan_content, scan_history, scan_single_file,
    ScanCache,
};
use velka::output::{format_output, OutputFormat, RedactionConfig};

const PRESET_STRICT: &str = r#"[scan]
ignore_paths = []
entropy_threshold = 4.0
max_file_size_mb = 100
skip_minified_threshold = 10000

[output]
redact_secrets = true
redact_visible_chars = 4

[cache]
enabled = true
location = "both"

[rules]
disable = []
"#;

const PRESET_BALANCED: &str = r#"[scan]
ignore_paths = [
  "tests/**",
  "docs/**",
  "examples/**",
  "vendor/**",
]
entropy_threshold = 4.6
max_file_size_mb = 50
skip_minified_threshold = 10000

[output]
redact_secrets = true
redact_visible_chars = 4

[cache]
enabled = true
location = "both"

[rules]
disable = []
"#;

const PRESET_CI: &str = r#"[scan]
ignore_paths = [
  "tests/**",
  "examples/**",
  "vendor/**",
]
entropy_threshold = 4.6
max_file_size_mb = 50
skip_minified_threshold = 10000

[output]
redact_secrets = true
redact_visible_chars = 4

[cache]
enabled = false
location = "both"

[rules]
disable = []
"#;

const PRESET_MONOREPO: &str = r#"[scan]
ignore_paths = [
  "dist/**",
  "build/**",
  ".next/**",
  "coverage/**",
  "node_modules/**",
  "vendor/**",
]
entropy_threshold = 4.6
max_file_size_mb = 80
skip_minified_threshold = 12000

[output]
redact_secrets = true
redact_visible_chars = 4

[cache]
enabled = true
location = "both"

[rules]
disable = []
"#;

#[derive(Parser)]
#[command(
    name = "velka",
    about = "The Code Sin Judge - Security Scanner",
    version
)]
enum Cli {
    Scan(ScanArgs),
    Stdin(StdinArgs),
    InstallHook,
    Init(InitArgs),
}

#[derive(Parser)]
#[allow(clippy::struct_excessive_bools)]
struct ScanArgs {
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(
        long,
        short,
        default_value = "terminal",
        help = "Output format: terminal, json, csv, junit, sarif, markdown, html, report"
    )]
    format: OutputFormat,

    #[arg(long, short, help = "Only report mortal sins")]
    mortal_only: bool,

    #[arg(long, help = "Scan git history for buried secrets")]
    deep_scan: bool,

    #[arg(long, help = "Enable complexity analysis")]
    complexity: bool,

    #[arg(long, help = "Disable secret redaction (show full secrets)")]
    no_redact: bool,

    #[arg(long, help = "Configuration profile to use")]
    profile: Option<String>,

    #[arg(long, help = "Only scan changed files (git diff)")]
    diff: bool,

    #[arg(long, help = "Only scan staged files (pre-commit mode)")]
    staged: bool,

    #[arg(long, help = "Show progress bar")]
    progress: bool,

    #[arg(
        long,
        help = "CI-friendly output (removes non-ASCII characters from markdown/html)"
    )]
    ci: bool,

    #[arg(
        long,
        help = "Verify secrets via API (GitHub token, etc.; makes network calls)"
    )]
    verify: bool,

    #[arg(long, help = "Migrate secrets to .env and update source files")]
    migrate_to_env: bool,

    #[arg(
        long,
        help = "Path to .env file (default: .env)",
        default_value = ".env"
    )]
    env_file: Option<PathBuf>,

    #[arg(long, help = "Show what would be done without writing")]
    dry_run: bool,

    #[arg(long, help = "Apply migration without confirmation")]
    yes: bool,
}

#[derive(Parser)]
struct StdinArgs {
    #[arg(
        long,
        short,
        default_value = "terminal",
        help = "Output format: terminal, json, csv, junit, sarif, markdown, html, report"
    )]
    format: OutputFormat,

    #[arg(long, short, help = "Only report mortal sins")]
    mortal_only: bool,

    #[arg(long, help = "Disable secret redaction (show full secrets)")]
    no_redact: bool,

    #[arg(long, help = "CI-friendly output")]
    ci: bool,
}

#[derive(Parser)]
struct InitArgs {
    #[arg(
        long,
        default_value = "balanced",
        value_parser = ["strict", "balanced", "ci", "monorepo"],
        help = "Configuration preset: strict, balanced, ci, monorepo"
    )]
    preset: String,

    #[arg(long, help = "Overwrite existing velka.toml if it already exists")]
    force: bool,
}

fn main() -> Result<()> {
    match Cli::parse() {
        Cli::Scan(args) => run_scan(&args),
        Cli::Stdin(args) => run_stdin(&args),
        Cli::InstallHook => install_pre_commit_hook(),
        Cli::Init(args) => run_init(&args),
    }
}

fn run_stdin(args: &StdinArgs) -> Result<()> {
    let mut content = String::new();
    std::io::stdin()
        .read_to_string(&mut content)
        .context("Read stdin")?;

    let config = VelkaConfig::load()?;
    let mut sins = scan_content(&content, &config)?;

    if args.mortal_only {
        sins.retain(|sin| sin.severity == Severity::Mortal);
    }

    sins.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.line_number.cmp(&b.line_number))
    });

    let redaction = RedactionConfig {
        enabled: !args.no_redact && config.output.redact_secrets,
        visible_chars: config.output.redact_visible_chars,
    };

    let has_mortal = sins.iter().any(|s| s.severity == Severity::Mortal);
    let output = format_output(sins, args.format, &redaction, args.ci);
    print!("{output}");

    if has_mortal {
        std::process::exit(1);
    }
    Ok(())
}

fn run_scan(args: &ScanArgs) -> Result<()> {
    let path = validate_scan_path(&args.path)?;

    if args.migrate_to_env {
        return run_migrate_flow(&path, args);
    }

    let mut config = VelkaConfig::load()?;

    if let Some(ref profile_name) = args.profile {
        config = config.with_profile(profile_name);
    }
    if args.verify {
        config.scan.verify = true;
    }

    let config = Arc::new(config);

    let redaction = RedactionConfig {
        enabled: !args.no_redact && config.output.redact_secrets,
        visible_chars: config.output.redact_visible_chars,
    };

    let (sender, receiver) = unbounded::<Sin>();

    let files_to_scan = if args.diff {
        match get_changed_files(&path) {
            Ok(files) => Some(files),
            Err(e) => {
                log_error("git diff", &e);
                None
            }
        }
    } else if args.staged {
        match get_staged_files(&path) {
            Ok(files) => Some(files),
            Err(e) => {
                log_error("git staged", &e);
                None
            }
        }
    } else {
        None
    };

    if let Some(files) = files_to_scan {
        if files.is_empty() {
            let output = format_output(vec![], args.format, &redaction, args.ci);
            print!("{output}");
            return Ok(());
        }

        let cache: Option<Arc<std::sync::RwLock<ScanCache>>> = if config.cache.enabled {
            Some(Arc::new(std::sync::RwLock::new(ScanCache::new(
                &config.cache.location,
                &path,
            ))))
        } else {
            None
        };

        for file_path in files {
            let file_sender = sender.clone();
            let file_config = Arc::clone(&config);
            let cache_clone = cache.clone();
            if let Err(e) =
                scan_single_file(&file_path, &file_config, &file_sender, cache_clone.as_ref())
            {
                if std::env::var("VELKA_DEBUG").is_ok() {
                    eprintln!("Error scanning {}: {}", file_path.display(), e);
                }
            }
        }

        if let Some(cache_rw) = cache {
            if let Ok(cache_guard) = cache_rw.write() {
                let _ = cache_guard.save();
            }
        }
    } else {
        let config_clone = Arc::clone(&config);
        let sender1 = sender.clone();
        let path_clone = path.clone();
        let show_progress = args.progress;
        std::thread::spawn(move || {
            if let Err(e) =
                investigate_with_progress(&path_clone, &config_clone, &sender1, show_progress)
            {
                log_error("scan", &e);
            }
        });
    }

    if args.deep_scan {
        let path_git = path.clone();
        let sender2 = sender.clone();
        let config_git = Arc::clone(&config);
        std::thread::spawn(move || {
            if let Err(e) = scan_history(&path_git, &config_git, &sender2) {
                log_error("git history", &e);
            }
        });
    }

    if args.complexity {
        let path_comp = path.clone();
        let sender3 = sender.clone();
        std::thread::spawn(move || {
            if let Err(e) = analyze_complexity(&path_comp, &sender3) {
                log_error("complexity", &e);
            }
        });
    }

    drop(sender);

    let mut sins: Vec<Sin> = receiver.iter().collect();

    if args.mortal_only {
        sins.retain(|sin| sin.severity == Severity::Mortal);
    }

    sins.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.line_number.cmp(&b.line_number))
    });

    let has_mortal = sins.iter().any(|s| s.severity == Severity::Mortal);

    let output = format_output(sins, args.format, &redaction, args.ci);
    print!("{output}");

    if has_mortal {
        std::process::exit(1);
    }

    Ok(())
}

fn run_init(args: &InitArgs) -> Result<()> {
    let config_path = PathBuf::from("velka.toml");

    if config_path.exists() && !args.force {
        anyhow::bail!(
            "velka.toml already exists. Use --force to overwrite the existing configuration."
        );
    }

    let contents = match args.preset.as_str() {
        "strict" => PRESET_STRICT,
        "ci" => PRESET_CI,
        "monorepo" => PRESET_MONOREPO,
        _ => PRESET_BALANCED,
    };

    fs::write(&config_path, contents)
        .with_context(|| format!("Failed to write configuration to {}", config_path.display()))?;

    println!(
        "velka.toml created with '{}' preset at {}",
        args.preset,
        config_path.display()
    );

    Ok(())
}

fn run_migrate_flow(path: &Path, args: &ScanArgs) -> Result<()> {
    let env_file = args.env_file.as_deref().unwrap_or(Path::new(".env"));

    if args.dry_run {
        let report =
            run_migrate(path, env_file, true, false).map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("{}", format_migrate_report(&report));
        return Ok(());
    }

    if args.yes {
        let report =
            run_migrate(path, env_file, false, true).map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("{}", format_migrate_report(&report));
        return Ok(());
    }

    let preview = run_migrate(path, env_file, true, false).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", format_migrate_report(&preview));
    print!(
        "Will update {} file(s) and create/update .env. Proceed? [y/N] ",
        preview.files_updated.len()
    );
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut buf = String::new();
    if std::io::stdin().read_line(&mut buf).is_ok()
        && (buf.trim().eq_ignore_ascii_case("y") || buf.trim().eq_ignore_ascii_case("yes"))
    {
        let report =
            run_migrate(path, env_file, false, true).map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("{}", format_migrate_report(&report));
    }
    Ok(())
}

fn validate_scan_path(path: &Path) -> Result<PathBuf> {
    let canonical = path.canonicalize().with_context(|| "Invalid scan path")?;

    let forbidden = ["/proc", "/sys", "/dev", "/etc/shadow", "/etc/passwd"];
    for prefix in forbidden {
        if canonical.starts_with(prefix) {
            anyhow::bail!("Scanning system paths is not allowed for security reasons");
        }
    }

    Ok(canonical)
}

fn log_error(context: &str, error: &dyn std::error::Error) {
    if std::env::var("VELKA_DEBUG").is_ok() {
        eprintln!("[VELKA DEBUG] Error during {context}: {error}");
    } else {
        eprintln!("Error during {context}: {}", sanitize_error(error));
    }
}

fn sanitize_error(_e: &dyn std::error::Error) -> String {
    "An error occurred (run with VELKA_DEBUG=1 for details)".to_string()
}

fn install_pre_commit_hook() -> Result<()> {
    use std::fs;

    let git_dir = PathBuf::from(".git");
    if !git_dir.exists() {
        anyhow::bail!("Not a git repository (.git directory not found)");
    }

    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)?;

    let hook_path = hooks_dir.join("pre-commit");

    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)?;
        if !existing.contains("Installed by Velka") {
            anyhow::bail!(
                "Pre-commit hook already exists and was not installed by Velka. \
                 Please backup and remove it manually, then retry."
            );
        }
    }

    let hook_content = r#"#!/bin/sh
# Installed by Velka
# Stops commit if Mortal Sins are found
velka scan . --mortal-only --staged 2>/dev/null || velka scan . --mortal-only
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo "Velka found mortal sins. Commit blocked."
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

    println!(
        "Pre-commit hook installed successfully at {}",
        hook_path.display()
    );
    Ok(())
}
