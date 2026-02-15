use std::fs;
use std::path::PathBuf;

use anyhow::Result;

pub fn install_pre_commit_hook(force: bool, strict: bool) -> Result<()> {
    let git_dir = PathBuf::from(".git");
    if !git_dir.exists() {
        anyhow::bail!("Not a git repository (.git directory not found)");
    }

    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)?;

    let hook_path = hooks_dir.join("pre-commit");

    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)?;
        if !existing.contains("Installed by Velka") && !force {
            anyhow::bail!(
                "Pre-commit hook already exists and was not installed by Velka. \
                 Use --force to overwrite, or backup and remove it manually."
            );
        }
    }

    let scan_flags = if strict {
        "--staged"
    } else {
        "--mortal-only --staged"
    };

    let hook_content = format!(
        r#"#!/bin/sh
# Installed by Velka (v2 - high-performance pre-commit guard)
# Mode: {}

# Use staged-only scan for speed
velka scan . {scan_flags} 2>/dev/null
exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo ""
    echo "============================================"
    echo "  VELKA: Secrets detected in staged files"
    echo "  Commit BLOCKED to prevent leakage."
    echo ""
    echo "  Run 'velka scan . --staged' for details."
    echo "  Run 'velka quarantine list' to manage."
    echo "============================================"
    exit 1
fi
"#,
        if strict { "strict" } else { "standard" }
    );

    fs::write(&hook_path, hook_content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }

    println!("Pre-commit hook installed at {}", hook_path.display());
    if strict {
        println!("Mode: strict (blocks all sins including venial)");
    } else {
        println!("Mode: standard (blocks mortal sins only)");
    }
    Ok(())
}
