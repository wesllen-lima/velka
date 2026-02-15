mod cli;
mod presets;

use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use clap_complete::{generate, Shell};

use velka::output::OutputFormat;

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
    Honeytoken(HoneytokenArgs),
    Rules(RulesArgs),
    Rotate(RotateArgs),
    Hook(HookArgs),
    Quarantine(QuarantineArgs),
    Lsp,
    Tui(TuiArgs),
    K8s(K8sArgs),
    Runtime(RuntimeArgs),
    /// Generate shell completion scripts
    Completions(CompletionsArgs),
}

#[derive(Parser)]
struct HoneytokenArgs {
    #[command(subcommand)]
    command: HoneytokenCommand,
}

#[derive(Parser)]
enum HoneytokenCommand {
    Generate(HoneytokenGenerateArgs),
}

#[derive(Parser)]
struct HoneytokenGenerateArgs {
    #[arg(long, help = "Target file to inject tokens (.env.example)")]
    target: Option<PathBuf>,

    #[arg(long, help = "Also inject to README.md")]
    readme: bool,
}

#[derive(Parser)]
struct RulesArgs {
    #[command(subcommand)]
    command: RulesCommand,
}

#[derive(Parser)]
enum RulesCommand {
    List,
    Install(RulesInstallArgs),
}

#[derive(Parser)]
struct RulesInstallArgs {
    #[arg(help = "URL or local path to a rules file (.toml or .yaml)")]
    source: String,

    #[arg(long, help = "Custom name for the installed rules file")]
    name: Option<String>,
}

#[derive(Parser)]
struct RotateArgs {
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(long, help = "Only show rotation guidance for a specific rule ID")]
    rule: Option<String>,

    #[arg(long, help = "Mark detected secrets as remediated in history file")]
    mark_remediated: bool,

    #[arg(
        long,
        help = "Print executable CLI commands for rotation (dry-run safe)"
    )]
    commands: bool,
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

    #[arg(
        long,
        help = "Incremental scan: only files changed since <commit/tag/branch>"
    )]
    since: Option<String>,
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
struct TuiArgs {
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(long, help = "Also scan git history")]
    deep_scan: bool,
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

#[derive(Parser)]
struct HookArgs {
    #[command(subcommand)]
    command: HookCommand,
}

#[derive(Parser)]
enum HookCommand {
    /// Install a high-performance pre-commit hook that blocks secrets
    Install(HookInstallArgs),
}

#[derive(Parser)]
struct HookInstallArgs {
    #[arg(long, help = "Overwrite existing non-Velka hook")]
    force: bool,

    #[arg(long, help = "Also block venial sins (stricter mode)")]
    strict: bool,
}

#[derive(Parser)]
struct CompletionsArgs {
    #[arg(help = "Target shell: bash, zsh, fish, elvish, powershell")]
    shell: Shell,
}

#[derive(Parser)]
struct K8sArgs {
    #[command(subcommand)]
    command: K8sCommand,
}

#[derive(Parser)]
enum K8sCommand {
    /// Start the Kubernetes admission webhook server
    Webhook(K8sWebhookArgs),
    /// Scan a local YAML manifest for secrets
    Scan(K8sScanArgs),
}

#[derive(Parser)]
struct K8sWebhookArgs {
    #[arg(
        long,
        default_value = "0.0.0.0:8443",
        help = "Address to bind the webhook server"
    )]
    addr: String,

    #[arg(long, help = "Path to TLS certificate file")]
    tls_cert: Option<String>,

    #[arg(long, help = "Path to TLS private key file")]
    tls_key: Option<String>,
}

#[derive(Parser)]
struct K8sScanArgs {
    #[arg(help = "Path to YAML manifest file")]
    file: PathBuf,
}

#[derive(Parser)]
struct RuntimeArgs {
    #[arg(help = "Log source paths to monitor (reads stdin if empty)")]
    sources: Vec<String>,

    #[arg(long, short, help = "Follow (tail) log files for new content")]
    follow: bool,
}

#[derive(Parser)]
struct QuarantineArgs {
    #[command(subcommand)]
    command: QuarantineCommand,
}

#[derive(Parser)]
enum QuarantineCommand {
    /// List quarantined files
    List,
    /// Restore a quarantined file to its original location
    Restore(QuarantineRestoreArgs),
}

#[derive(Parser)]
struct QuarantineRestoreArgs {
    #[arg(help = "Name of the quarantined file")]
    name: String,
}

fn main() -> Result<()> {
    match Cli::parse() {
        Cli::Scan(args) => cli::scan::run_scan(
            &args.path,
            args.format,
            args.mortal_only,
            args.deep_scan,
            args.complexity,
            args.no_redact,
            args.profile.as_deref(),
            args.diff,
            args.staged,
            args.progress,
            args.ci,
            args.verify,
            args.migrate_to_env,
            args.env_file.as_deref(),
            args.dry_run,
            args.yes,
            args.since.as_deref(),
        ),
        Cli::Stdin(args) => {
            cli::scan::run_stdin(args.format, args.mortal_only, args.no_redact, args.ci)
        }
        Cli::InstallHook => cli::hooks::install_pre_commit_hook(false, false),
        Cli::Init(args) => cli::init::run_init(&args.preset, args.force),
        Cli::Honeytoken(args) => match args.command {
            HoneytokenCommand::Generate(gen) => {
                cli::scan::run_honeytoken(gen.target.as_deref(), gen.readme)
            }
        },
        Cli::Rules(args) => match args.command {
            RulesCommand::List => cli::scan::run_rules_list(),
            RulesCommand::Install(install) => {
                cli::scan::run_rules_install(&install.source, install.name.as_deref())
            }
        },
        Cli::Rotate(args) => cli::rotate::run_rotate(
            &args.path,
            args.rule.as_deref(),
            args.mark_remediated,
            args.commands,
        ),
        Cli::Hook(args) => match args.command {
            HookCommand::Install(install) => {
                cli::hooks::install_pre_commit_hook(install.force, install.strict)
            }
        },
        Cli::Quarantine(args) => match args.command {
            QuarantineCommand::List => cli::scan::run_quarantine_list(),
            QuarantineCommand::Restore(restore) => cli::scan::run_quarantine_restore(&restore.name),
        },
        Cli::Lsp => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(velka::engine::lsp::run_lsp())?;
            Ok(())
        }
        Cli::Tui(args) => velka::ui::run_tui(&args.path, args.deep_scan),
        Cli::Completions(args) => {
            generate(
                args.shell,
                &mut Cli::command(),
                "velka",
                &mut std::io::stdout(),
            );
            Ok(())
        }
        Cli::K8s(args) => match args.command {
            K8sCommand::Webhook(w) => {
                cli::scan::run_k8s_webhook(&w.addr, w.tls_cert.as_deref(), w.tls_key.as_deref())
            }
            K8sCommand::Scan(s) => cli::scan::run_k8s_scan(&s.file),
        },
        Cli::Runtime(args) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(velka::engine::runtime_scanner::run_runtime_monitor(
                args.sources,
                args.follow,
            ))?;
            Ok(())
        }
    }
}
