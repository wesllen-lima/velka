use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use crossbeam_channel::unbounded;

use velka::config::VelkaConfig;
use velka::domain::{Severity, Sin};
use velka::engine::{
    analyze_complexity, generate_all, get_changed_files, get_changed_files_since,
    get_diff_line_ranges_since, get_staged_files, inject_to_file, inject_to_readme,
    investigate_with_progress, scan_content, scan_history, scan_single_file, DynamicRulesManager,
    ScanCache,
};
use velka::output::{format_output, OutputFormat, RedactionConfig};

use super::init::run_migrate_flow;

pub fn run_honeytoken(target: Option<&Path>, readme: bool) -> Result<()> {
    let tokens = generate_all();

    let target = target.map_or_else(|| PathBuf::from(".env.example"), Path::to_path_buf);

    inject_to_file(&target, &tokens)?;
    println!("\u{2713} Honeytokens injected to {}", target.display());

    if readme {
        let readme_path = PathBuf::from("README.md");
        inject_to_readme(&readme_path, &tokens)?;
        println!("\u{2713} Honeytokens injected to README.md");
    }

    println!("\nGenerated {} honeytokens:", tokens.len());
    for (key, token) in tokens {
        println!("  {} -> {}", key, token.token_type);
    }

    Ok(())
}

pub fn run_rules_list() -> Result<()> {
    let manager =
        DynamicRulesManager::new(None).map_err(|e| anyhow::anyhow!("Failed to load rules: {e}"))?;

    let rules = manager.list_rules();

    if rules.is_empty() {
        println!("No dynamic rules found in ~/.velka/rules.d/");
        println!("\nCreate .toml or .yaml files in that directory to add custom rules.");
        return Ok(());
    }

    println!("Dynamic Rules ({}):", rules.len());
    println!("{:<30} {:<50} Severity", "ID", "Description");
    println!("{}", "-".repeat(90));

    for (id, desc, severity) in rules {
        println!("{id:<30} {desc:<50} {severity}");
    }

    Ok(())
}

pub fn run_rules_install(source: &str, name: Option<&str>) -> Result<()> {
    let rules_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".velka")
        .join("rules.d");
    fs::create_dir_all(&rules_dir)?;

    let is_url = source.starts_with("http://") || source.starts_with("https://");

    let (content, detected_ext) = if is_url {
        let response = reqwest::blocking::get(source)
            .with_context(|| format!("Failed to fetch rules from {source}"))?;

        if !response.status().is_success() {
            anyhow::bail!("HTTP {} fetching {}", response.status(), source);
        }

        let body = response
            .text()
            .with_context(|| "Failed to read response body")?;

        let source_path = Path::new(source);
        let ext = if source_path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
        {
            "yaml"
        } else {
            "toml"
        };

        (body, ext)
    } else {
        let path = Path::new(source);
        if !path.exists() {
            anyhow::bail!("File not found: {source}");
        }
        let body = fs::read_to_string(path).with_context(|| format!("Failed to read {source}"))?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("toml");
        (body, ext)
    };

    if detected_ext == "toml" {
        toml::from_str::<toml::Value>(&content).with_context(|| "Invalid TOML rules file")?;
    } else {
        serde_yaml::from_str::<serde_yaml::Value>(&content)
            .with_context(|| "Invalid YAML rules file")?;
    }

    let file_name = if let Some(name) = name {
        format!("{name}.{detected_ext}")
    } else if is_url {
        let url_path = source.rsplit('/').next().unwrap_or("community-rules");
        if url_path.contains('.') {
            url_path.to_string()
        } else {
            format!("{url_path}.{detected_ext}")
        }
    } else {
        Path::new(source).file_name().map_or_else(
            || format!("installed-rules.{detected_ext}"),
            |f| f.to_string_lossy().to_string(),
        )
    };

    let dest = rules_dir.join(&file_name);
    fs::write(&dest, &content)?;

    let manager = DynamicRulesManager::new(Some(rules_dir))
        .map_err(|e| anyhow::anyhow!("Rules validation failed: {e}"))?;

    let count = manager.list_rules().len();
    println!("Installed {file_name} to {}", dest.display());
    println!("{count} total dynamic rules loaded.");

    Ok(())
}

pub fn run_stdin(format: OutputFormat, mortal_only: bool, no_redact: bool, ci: bool) -> Result<()> {
    let mut content = String::new();
    std::io::stdin()
        .read_to_string(&mut content)
        .context("Read stdin")?;

    let config = VelkaConfig::load()?;
    let mut sins = scan_content(&content, &config)?;

    if mortal_only {
        sins.retain(|sin| sin.severity == Severity::Mortal);
    }

    sins.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.line_number.cmp(&b.line_number))
    });

    let redaction = RedactionConfig {
        enabled: !no_redact && config.output.redact_secrets,
        visible_chars: config.output.redact_visible_chars,
    };

    let has_mortal = sins.iter().any(|s| s.severity == Severity::Mortal);
    let output = format_output(sins, format, &redaction, ci);
    print!("{output}");

    if has_mortal {
        std::process::exit(1);
    }
    Ok(())
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
pub fn run_scan(
    path: &Path,
    format: OutputFormat,
    mortal_only: bool,
    deep_scan: bool,
    complexity: bool,
    no_redact: bool,
    profile: Option<&str>,
    diff: bool,
    staged: bool,
    progress: bool,
    ci: bool,
    verify: bool,
    migrate_to_env: bool,
    env_file: Option<&Path>,
    dry_run: bool,
    yes: bool,
    since: Option<&str>,
) -> Result<()> {
    let path = validate_scan_path(path)?;

    if migrate_to_env {
        return run_migrate_flow(&path, env_file, dry_run, yes);
    }

    let num_threads = compute_adaptive_threads(&path);
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .ok();

    let mut config = VelkaConfig::load()?;

    if let Some(profile_name) = profile {
        config = config.with_profile(profile_name);
    }
    if verify {
        config.scan.verify = true;
    }

    let config = Arc::new(config);

    let redaction = RedactionConfig {
        enabled: !no_redact && config.output.redact_secrets,
        visible_chars: config.output.redact_visible_chars,
    };

    let (sender, receiver) = unbounded::<Sin>();

    let since_line_ranges = if let Some(since_ref) = since {
        match get_diff_line_ranges_since(&path, since_ref) {
            Ok(ranges) => Some(ranges),
            Err(e) => {
                log_error("git diff --since", &e);
                None
            }
        }
    } else {
        None
    };

    let files_to_scan = if let Some(since_ref) = since {
        match get_changed_files_since(&path, since_ref) {
            Ok(files) => Some(files),
            Err(e) => {
                log_error("git since", &e);
                None
            }
        }
    } else if diff {
        match get_changed_files(&path) {
            Ok(files) => Some(files),
            Err(e) => {
                log_error("git diff", &e);
                None
            }
        }
    } else if staged {
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
            let output = format_output(vec![], format, &redaction, ci);
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
        std::thread::spawn(move || {
            if let Err(e) =
                investigate_with_progress(&path_clone, &config_clone, &sender1, progress)
            {
                log_error("scan", &e);
            }
        });
    }

    if deep_scan {
        let path_git = path.clone();
        let sender2 = sender.clone();
        let config_git = Arc::clone(&config);
        std::thread::spawn(move || {
            if let Err(e) = scan_history(&path_git, &config_git, &sender2) {
                log_error("git history", &e);
            }
        });
    }

    if complexity {
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

    if let Some(ref ranges) = since_line_ranges {
        sins.retain(|sin| {
            let sin_path = PathBuf::from(&sin.path);
            if let Some(file_ranges) = ranges.get(&sin_path) {
                file_ranges
                    .iter()
                    .any(|(start, end)| sin.line_number >= *start && sin.line_number < *end)
            } else {
                true
            }
        });
    }

    if mortal_only {
        sins.retain(|sin| sin.severity == Severity::Mortal);
    }

    sins.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.line_number.cmp(&b.line_number))
    });

    let has_mortal = sins.iter().any(|s| s.severity == Severity::Mortal);

    let output = format_output(sins, format, &redaction, ci);
    print!("{output}");

    if has_mortal {
        std::process::exit(1);
    }

    Ok(())
}

pub fn run_quarantine_list() -> Result<()> {
    let repo_root = PathBuf::from(".").canonicalize()?;
    let entries = velka::engine::quarantine::list_quarantined(&repo_root)?;
    if entries.is_empty() {
        println!("No quarantined files.");
    } else {
        println!("Quarantined files ({}):", entries.len());
        for name in &entries {
            let original = name.replace("__", "/");
            println!("  {name} (original: {original})");
        }
    }
    Ok(())
}

pub fn run_quarantine_restore(name: &str) -> Result<()> {
    let repo_root = PathBuf::from(".").canonicalize()?;
    let restored = velka::engine::quarantine::restore_file(&repo_root, name)?;
    println!("Restored to {}", restored.display());
    Ok(())
}

pub fn run_k8s_webhook(addr: &str, tls_cert: Option<&str>, tls_key: Option<&str>) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(velka::engine::k8s::run_admission_webhook(
        addr, tls_cert, tls_key,
    ))?;
    Ok(())
}

pub fn run_k8s_scan(file: &Path) -> Result<()> {
    let content =
        fs::read_to_string(file).with_context(|| format!("Failed to read {}", file.display()))?;

    let sins = velka::engine::k8s::scan_k8s_manifest(&content)?;

    if sins.is_empty() {
        println!("No secrets found in manifest.");
    } else {
        let mortal_count = sins
            .iter()
            .filter(|s| s.severity == velka::domain::Severity::Mortal)
            .count();

        println!(
            "Found {} finding(s) ({} mortal) in {}:",
            sins.len(),
            mortal_count,
            file.display()
        );

        for sin in &sins {
            println!(
                "  [{}] {} (line {}): {}",
                sin.rule_id, sin.description, sin.line_number, sin.snippet
            );
        }

        if mortal_count > 0 {
            std::process::exit(1);
        }
    }

    Ok(())
}

pub fn validate_scan_path(path: &Path) -> Result<PathBuf> {
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
        eprintln!("Error during {context}: An error occurred (run with VELKA_DEBUG=1 for details)");
    }
}

fn compute_adaptive_threads(path: &Path) -> usize {
    let cpu_count = num_cpus::get();
    let file_count = ignore::WalkBuilder::new(path)
        .hidden(false)
        .git_ignore(true)
        .build()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().is_file())
        .count();

    if file_count < 100 {
        cpu_count.min(4)
    } else if file_count < 1000 {
        cpu_count
    } else {
        (cpu_count * 2).min(16)
    }
}
