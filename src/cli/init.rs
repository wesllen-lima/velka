use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::presets::{PRESET_BALANCED, PRESET_CI, PRESET_MONOREPO, PRESET_STRICT};
use velka::engine::{format_migrate_report, run_migrate};

pub fn run_init(preset: &str, force: bool) -> Result<()> {
    let config_path = PathBuf::from("velka.toml");

    if config_path.exists() && !force {
        anyhow::bail!(
            "velka.toml already exists. Use --force to overwrite the existing configuration."
        );
    }

    let contents = match preset {
        "strict" => PRESET_STRICT,
        "ci" => PRESET_CI,
        "monorepo" => PRESET_MONOREPO,
        _ => PRESET_BALANCED,
    };

    fs::write(&config_path, contents)
        .with_context(|| format!("Failed to write configuration to {}", config_path.display()))?;

    println!(
        "velka.toml created with '{}' preset at {}",
        preset,
        config_path.display()
    );

    Ok(())
}

pub fn run_migrate_flow(
    path: &Path,
    env_file: Option<&Path>,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let env_file = env_file.unwrap_or(Path::new(".env"));

    if dry_run {
        let report =
            run_migrate(path, env_file, true, false).map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("{}", format_migrate_report(&report));
        return Ok(());
    }

    if yes {
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
