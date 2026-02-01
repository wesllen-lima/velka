pub mod config;
pub mod domain;
pub mod engine;
pub mod error;
pub mod output;
pub mod utils;

use std::path::Path;
use std::sync::Arc;

use crossbeam_channel::unbounded;

pub use config::VelkaConfig;
pub use domain::{Severity, Sin};
pub use error::{Result as VelkaResult, VelkaError};
pub use output::{OutputFormat, RedactionConfig};

/// Options for customizing scan behavior
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct ScanOptions {
    /// Scan git commit history for secrets
    pub deep_scan: bool,
    /// Analyze code complexity
    pub complexity: bool,
    /// Only scan changed files (git diff)
    pub diff_only: bool,
    /// Only scan staged files (git staged)
    pub staged_only: bool,
}

/// Scan a directory for secrets using default configuration
///
/// # Example
/// ```no_run
/// use velka::scan;
/// # fn main() -> velka::VelkaResult<()> {
/// let sins = scan(std::path::Path::new("."))?;
/// # Ok(())
/// # }
/// ```
pub fn scan(path: &Path) -> VelkaResult<Vec<Sin>> {
    let config = VelkaConfig::load()?;
    scan_with_config(path, &config)
}

/// Scan a directory with a custom configuration
///
/// # Example
/// ```no_run
/// use velka::{scan_with_config, VelkaConfig};
/// # fn main() -> velka::VelkaResult<()> {
/// let config = VelkaConfig::default();
/// let sins = scan_with_config(std::path::Path::new("."), &config)?;
/// # Ok(())
/// # }
/// ```
pub fn scan_with_config(path: &Path, config: &VelkaConfig) -> VelkaResult<Vec<Sin>> {
    let (sender, receiver) = unbounded();

    engine::investigate(path, config, &sender)?;
    drop(sender);

    let sins: Vec<Sin> = receiver.iter().collect();
    Ok(sins)
}

/// Scan a directory with custom options (deep scan, complexity, diff/staged)
///
/// # Example
/// ```no_run
/// use velka::{scan_with_options, ScanOptions};
/// # fn main() -> velka::VelkaResult<()> {
/// let options = ScanOptions {
///     deep_scan: true,
///     complexity: false,
///     diff_only: false,
///     staged_only: false,
/// };
/// let sins = scan_with_options(std::path::Path::new("."), &options)?;
/// # Ok(())
/// # }
/// ```
pub fn scan_with_options(path: &Path, options: &ScanOptions) -> VelkaResult<Vec<Sin>> {
    let config = Arc::new(VelkaConfig::load()?);

    let (sender, receiver) = unbounded();

    let files_to_scan = if options.diff_only {
        Some(engine::get_changed_files(path)?)
    } else if options.staged_only {
        Some(engine::get_staged_files(path)?)
    } else {
        None
    };

    if let Some(files) = files_to_scan {
        for file_path in files {
            let file_sender = sender.clone();
            let file_config = Arc::clone(&config);
            if let Err(e) = engine::investigate(&file_path, &file_config, &file_sender) {
                if std::env::var("VELKA_DEBUG").is_ok() {
                    eprintln!("Error scanning {}: {}", file_path.display(), e);
                }
            }
        }
    } else {
        engine::investigate(path, &config, &sender)?;
    }

    if options.deep_scan {
        let git_sender = sender.clone();
        let git_config = Arc::clone(&config);
        let _ = engine::scan_history(path, &git_config, &git_sender);
    }

    if options.complexity {
        let comp_sender = sender.clone();
        let _ = engine::analyze_complexity(path, &comp_sender);
    }

    drop(sender);

    let sins: Vec<Sin> = receiver.iter().collect();
    Ok(sins)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::scan_content;

    #[test]
    fn test_scan_empty_dir() {
        let config = VelkaConfig::default();
        let result = scan_content("fn main() {}", &config);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_scan_with_secret() {
        let config = VelkaConfig::default();
        let result = scan_content(r#"let key = "AKIA0000000000000000";"#, &config);
        assert!(result.is_ok());
        let sins = result.unwrap();
        assert!(!sins.is_empty());
        assert!(sins.iter().any(|s| s.rule_id == "AWS_ACCESS_KEY"));
    }
}
