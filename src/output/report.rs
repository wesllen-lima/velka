use std::collections::HashMap;

use crate::domain::Severity;
use crate::domain::Sin;

#[derive(Debug, Clone)]
pub struct Report {
    pub files: Vec<FileReport>,
    pub mortal_count: usize,
    pub venial_count: usize,
}

#[derive(Debug, Clone)]
pub struct FileReport {
    pub path: String,
    pub sins: Vec<Sin>,
}

#[must_use]
pub fn build_report(sins: Vec<Sin>) -> Report {
    let mortal_count = sins
        .iter()
        .filter(|s| s.severity == Severity::Mortal)
        .count();
    let venial_count = sins.len() - mortal_count;

    let mut by_path: HashMap<String, Vec<Sin>> = HashMap::new();
    for sin in sins {
        by_path.entry(sin.path.clone()).or_default().push(sin);
    }

    let mut files: Vec<FileReport> = by_path
        .into_iter()
        .map(|(path, mut file_sins)| {
            file_sins.sort_by_key(|s| s.line_number);
            FileReport {
                path,
                sins: file_sins,
            }
        })
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));

    Report {
        files,
        mortal_count,
        venial_count,
    }
}
