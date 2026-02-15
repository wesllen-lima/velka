mod analyzer;
mod cache;
mod complexity;
pub mod dist;
mod file_reader;
mod honeytoken;
mod incremental;
pub mod k8s;
mod known_examples;
pub mod lsp;
mod migrate;
pub mod ml_classifier;
mod necromancer;
pub mod quarantine;
pub mod remediate;
mod rules;
pub mod runtime_scanner;
mod scanner;
pub mod vault;
mod verifier;

pub use known_examples::is_known_example;

pub use analyzer::{analyze_line, AnalyzeLineConfig};
pub use cache::{CacheEntry, CachedMatch, ScanCache};
pub use complexity::analyze_complexity;
pub use file_reader::{is_binary, read_file_content};
pub use honeytoken::{
    generate_all, inject_to_file, inject_to_readme, is_honeytoken, load_honeytokens, HoneyToken,
};
pub use incremental::{
    get_changed_files, get_changed_files_since, get_diff_line_ranges_since, get_staged_files,
};
pub use necromancer::scan_history;
pub use rules::{CompiledCustomRule, DynamicRulesManager, RULES};
pub use scanner::{investigate, investigate_with_progress, scan_content, scan_single_file};

pub use migrate::{
    check_env_in_gitignore, check_env_tracked, format_migrate_report, run_migrate, MigrateReport,
};
