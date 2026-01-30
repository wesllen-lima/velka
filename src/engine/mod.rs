mod analyzer;
mod cache;
mod complexity;
mod file_reader;
mod incremental;
mod necromancer;
mod rules;
mod scanner;
mod verifier;

pub use analyzer::{analyze_line, AnalyzeLineConfig};
pub use cache::{CacheEntry, CachedMatch, ScanCache};
pub use complexity::analyze_complexity;
pub use file_reader::{is_binary, read_file_content};
pub use incremental::{get_changed_files, get_staged_files};
pub use necromancer::scan_history;
pub use rules::{CompiledCustomRule, RULES};
pub use scanner::{investigate, investigate_with_progress, scan_content, scan_single_file};
