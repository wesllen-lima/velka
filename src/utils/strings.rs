#[must_use]
pub fn extract_quoted_strings(line: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut in_double = false;
    let mut in_single = false;
    let mut start = 0;

    for (i, ch) in line.char_indices() {
        match ch {
            '"' if !in_single => {
                if in_double {
                    let content_len = i - start - 1;
                    if content_len > 20 {
                        ranges.push((start + 1, i));
                    }
                    in_double = false;
                } else {
                    in_double = true;
                    start = i;
                }
            }
            '\'' if !in_double => {
                if in_single {
                    let content_len = i - start - 1;
                    if content_len > 20 {
                        ranges.push((start + 1, i));
                    }
                    in_single = false;
                } else {
                    in_single = true;
                    start = i;
                }
            }
            _ => {}
        }
    }

    ranges
}

pub fn extract_quoted_string_contents(line: &str) -> impl Iterator<Item = &str> {
    extract_quoted_strings(line)
        .into_iter()
        .filter_map(move |(start, end)| line.get(start..end))
}

#[must_use]
pub fn build_context<'a>(lines: &'a [&'a str], line_idx: usize) -> [&'a str; 3] {
    [
        if line_idx > 0 {
            lines[line_idx - 1]
        } else {
            ""
        },
        lines[line_idx],
        if line_idx + 1 < lines.len() {
            lines[line_idx + 1]
        } else {
            ""
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_quoted_strings() {
        let line = r#"let key = "AKIAIOSFODNN7EXAMPLE123";"#;
        let ranges = extract_quoted_strings(line);
        assert_eq!(ranges.len(), 1);
        assert_eq!(&line[ranges[0].0..ranges[0].1], "AKIAIOSFODNN7EXAMPLE123");
    }

    #[test]
    fn test_extract_short_strings_ignored() {
        let line = r#"let x = "short";"#;
        let ranges = extract_quoted_strings(line);
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_build_context() {
        let lines = vec!["line1", "line2", "line3", "line4"];
        let ctx = build_context(&lines, 1);
        assert_eq!(ctx, ["line1", "line2", "line3"]);
    }

    #[test]
    fn test_build_context_first_line() {
        let lines = vec!["line1", "line2", "line3"];
        let ctx = build_context(&lines, 0);
        assert_eq!(ctx, ["", "line1", "line2"]);
    }

    #[test]
    fn test_build_context_last_line() {
        let lines = vec!["line1", "line2", "line3"];
        let ctx = build_context(&lines, 2);
        assert_eq!(ctx, ["line2", "line3", ""]);
    }
}
