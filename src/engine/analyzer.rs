use regex::Regex;
use std::sync::LazyLock;

use crate::domain::Severity;
use crate::domain::Sin;
use crate::engine::known_examples::is_known_example;
use crate::engine::rules::CompiledCustomRule;
use crate::engine::RULES;
use crate::utils::{calculate_entropy, extract_quoted_string_contents};

static EXAMPLE_VAR_REGEXES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let suspicious_keywords = [
        "example",
        "test",
        "fake",
        "placeholder",
        "dummy",
        "sample",
        "demo",
    ];

    suspicious_keywords
        .iter()
        .map(|keyword| {
            Regex::new(&format!(
                r"(?i)(let|const|var|key|token|secret|password|api[_-]?key)\s+\w*{}\w*\s*=",
                regex::escape(keyword)
            ))
            .expect("invalid suspicious keyword regex")
        })
        .collect()
});

static COMMENT_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)//\s*(example|test|fake|sample|demo|placeholder)")
            .expect("invalid comment pattern"),
        Regex::new(r"(?i)#\s*(example|test)").expect("invalid comment pattern"),
        Regex::new(r"(?i)(example|test):").expect("invalid comment pattern"),
    ]
});

static EXAMPLE_VALUE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)^(example|test|fake|sample|demo|placeholder|dummy)[\d_-]*$")
            .expect("invalid example value pattern"),
        Regex::new(r"(?i)^[\d_-]*(example|test|fake|sample|demo|placeholder|dummy)$")
            .expect("invalid example value pattern"),
        Regex::new(r"(?i)^(example|test|fake|sample|demo|placeholder|dummy)[\d_-]{0,5}$")
            .expect("invalid example value pattern"),
    ]
});

static PLACEHOLDER_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)^(xxx+|XXX+|\*{3,}|-{3,}|_{3,})$").expect("placeholder regex"),
        Regex::new(r"(?i)(your[-_]?api[-_]?key|insert[-_]?token|replace[-_]?me|changeme|todo|placeholder)[-_]?(here)?$")
            .expect("placeholder regex"),
        Regex::new(r"^<[^>]+>$").expect("doc angle bracket"),
        Regex::new(r"(?i)^.*(TODO|CHANGEME|REPLACE|FIXME|XXX)\s*$").expect("doc keyword"),
    ]
});

fn looks_like_repetitive(matched: &str) -> bool {
    if matched.len() < 8 {
        return false;
    }
    let bytes = matched.as_bytes();
    let first = bytes[0];
    if bytes.iter().all(|&b| b == first) {
        return true;
    }
    if matched.chars().all(|c| c.is_ascii_digit()) && matched.len() >= 12 {
        let uniq: std::collections::HashSet<char> = matched.chars().collect();
        if uniq.len() <= 3 {
            return true;
        }
    }
    false
}

fn looks_like_placeholder(matched: &str) -> bool {
    let s = matched.trim();
    if s.len() > 80 {
        return false;
    }
    PLACEHOLDER_PATTERNS.iter().any(|re| re.is_match(s))
}

pub struct AnalyzeLineConfig<'a> {
    pub entropy_threshold: f32,
    pub disabled_rules: &'a [String],
    pub whitelist: &'a [String],
    pub custom_rules: &'a [CompiledCustomRule],
    pub skip_entropy_in_regex_context: bool,
    pub allowlist_regexes: Option<&'a [Regex]>,
}

fn is_whitelisted(matched: &str, whitelist: &[String]) -> bool {
    whitelist.iter().any(|w| matched.contains(w))
}

fn is_allowlisted_regex(matched: &str, allowlist_regexes: Option<&[Regex]>) -> bool {
    let Some(regexes) = allowlist_regexes else {
        return false;
    };
    regexes.iter().any(|re| re.is_match(matched))
}

fn path_suggests_test(path_str: &str) -> bool {
    let normalized = path_str.replace('\\', "/");
    normalized.contains("/tests/")
        || normalized.contains("/test/")
        || normalized.contains("/__tests__/")
        || normalized.contains("/spec/")
        || normalized.contains(".spec.")
        || normalized.contains("_test.")
        || normalized.contains(".test.")
}

fn line_suggests_test_context(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.contains("#[cfg(test)]")
        || trimmed.contains("#[test]")
        || trimmed.contains("#[cfg(test)")
        || trimmed.contains("fn test_")
        || trimmed.contains("def test_")
        || trimmed.contains("function test_")
}

static DOC_COMMENT_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)^\s*///\s*(example|test|fake|sample|demo|placeholder)")
            .expect("doc comment pattern"),
        Regex::new(r"(?i)^\s*/\*\*?\s*(example|test|fake|sample|demo|placeholder)")
            .expect("doc comment pattern"),
        Regex::new(r"(?i)^\s*#\s*(example|test)\b").expect("doc comment pattern"),
    ]
});

fn analyze_context(
    context: &[&str],
    line: &str,
    matched_value: Option<&str>,
    path_str: &str,
) -> bool {
    if path_suggests_test(path_str) {
        return true;
    }
    if line_suggests_test_context(line) {
        return true;
    }
    for ctx_line in context {
        if line_suggests_test_context(ctx_line) {
            return true;
        }
        for pattern in DOC_COMMENT_PATTERNS.iter() {
            if pattern.is_match(ctx_line.trim()) {
                return true;
            }
        }
    }
    for var_pattern in EXAMPLE_VAR_REGEXES.iter() {
        if var_pattern.is_match(line) {
            return true;
        }
    }

    if let Some(value) = matched_value {
        if value.len() <= 80 {
            for pattern in EXAMPLE_VALUE_PATTERNS.iter() {
                if pattern.is_match(value.trim()) {
                    return true;
                }
            }
            if looks_like_repetitive(value) || looks_like_placeholder(value) {
                return true;
            }
        }
    }

    if !context.is_empty() {
        let prev_line = context[0];
        for pattern in COMMENT_PATTERNS.iter() {
            if pattern.is_match(prev_line) {
                return true;
            }
        }
    }

    false
}

fn context_to_vec(context: &[&str; 3]) -> Vec<String> {
    context
        .iter()
        .map(std::string::ToString::to_string)
        .collect()
}

fn is_regex_context(line: &str) -> bool {
    let lower = line.to_lowercase();

    lower.contains("regex::new")
        || lower.contains("define_regex!")
        || lower.contains("pattern:")
        || lower.contains("re.compile")
        || lower.contains("new regexp")
        || lower.contains("new regex")
        || lower.contains("regexp")
        || lower.contains("regex")
        || lower.contains("(?i)")
}

#[must_use]
pub fn analyze_line(
    line: &str,
    path_str: &str,
    line_num: usize,
    context: [&str; 3],
    commit_hash: Option<String>,
    scan_cfg: &AnalyzeLineConfig<'_>,
) -> Option<Sin> {
    let entropy_threshold = scan_cfg.entropy_threshold;
    let disabled_rules = scan_cfg.disabled_rules;
    let whitelist = scan_cfg.whitelist;
    let custom_rules = scan_cfg.custom_rules;
    for rule in RULES {
        if disabled_rules.iter().any(|r| r == rule.id) {
            continue;
        }

        if let Some(mat) = rule.pattern.find(line) {
            let matched = mat.as_str();

            if is_whitelisted(matched, whitelist) {
                continue;
            }

            if analyze_context(&context, line, Some(matched), path_str) {
                continue;
            }

            if is_known_example(rule.id, matched) {
                continue;
            }

            if is_allowlisted_regex(matched, scan_cfg.allowlist_regexes) {
                continue;
            }

            if rule.id == "CREDIT_CARD" && !crate::utils::luhn_is_valid(matched) {
                continue;
            }

            if rule.id == "BRAZILIAN_CPF" && !crate::engine::compliance::validate_cpf(matched) {
                continue;
            }

            if rule.id == "BRAZILIAN_CNPJ" && !crate::engine::compliance::validate_cnpj(matched) {
                continue;
            }

            if rule.id == "DSN_CREDENTIALS"
                && crate::engine::compliance::extract_dsn_password(matched).is_none()
            {
                continue;
            }

            return Some(Sin {
                path: path_str.to_string(),
                line_number: line_num,
                snippet: line.trim().to_string(),
                context: context_to_vec(&context),
                severity: rule.severity,
                description: rule.description.to_string(),
                rule_id: rule.id.to_string(),
                commit_hash,
                verified: None,
                confidence: None,
                confidence_factors: None,
                confidence_level: None,
            });
        }
    }

    for custom_rule in custom_rules {
        if disabled_rules.iter().any(|r| r == &custom_rule.id) {
            continue;
        }

        if let Some(mat) = custom_rule.pattern.find(line) {
            let matched = mat.as_str();

            if is_whitelisted(matched, whitelist) {
                continue;
            }

            if analyze_context(&context, line, Some(matched), path_str) {
                continue;
            }

            if is_allowlisted_regex(matched, scan_cfg.allowlist_regexes) {
                continue;
            }

            return Some(Sin {
                path: path_str.to_string(),
                line_number: line_num,
                snippet: line.trim().to_string(),
                context: context_to_vec(&context),
                severity: custom_rule.severity,
                description: custom_rule.description.clone(),
                rule_id: custom_rule.id.clone(),
                commit_hash,
                verified: None,
                confidence: None,
                confidence_factors: None,
                confidence_level: None,
            });
        }
    }

    for string in extract_quoted_string_contents(line) {
        if is_whitelisted(string, whitelist) {
            continue;
        }

        if analyze_context(&context, line, Some(string), path_str) {
            continue;
        }

        if scan_cfg.skip_entropy_in_regex_context && is_regex_context(line) {
            continue;
        }

        if is_allowlisted_regex(string, scan_cfg.allowlist_regexes) {
            continue;
        }

        let entropy = calculate_entropy(string);
        if entropy > entropy_threshold {
            return Some(Sin {
                path: path_str.to_string(),
                line_number: line_num,
                snippet: line.trim().to_string(),
                context: context_to_vec(&context),
                severity: Severity::Mortal,
                description: "High entropy string detected (potential secret)".to_string(),
                rule_id: "HIGH_ENTROPY".to_string(),
                commit_hash,
                verified: None,
                confidence: None,
                confidence_factors: None,
                confidence_level: None,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Severity;

    fn default_config<'a>(
        disabled_rules: &'a [String],
        whitelist: &'a [String],
        custom_rules: &'a [CompiledCustomRule],
    ) -> AnalyzeLineConfig<'a> {
        AnalyzeLineConfig {
            entropy_threshold: 4.0,
            disabled_rules,
            whitelist,
            custom_rules,
            skip_entropy_in_regex_context: false,
            allowlist_regexes: None,
        }
    }

    #[test]
    fn test_analyze_line_aws_key() {
        let line = r#"let key = "AKIA0000000000000000";"#;
        let context = ["", line, ""];
        let scan_cfg = default_config(&[], &[], &[]);
        let result = analyze_line(line, "test.rs", 1, context, None, &scan_cfg);
        assert!(result.is_some());
        let sin = result.unwrap();
        assert_eq!(sin.rule_id, "AWS_ACCESS_KEY");
        assert_eq!(sin.severity, Severity::Mortal);
    }

    #[test]
    fn test_analyze_line_no_match() {
        let line = r"let x = 42;";
        let context = ["", line, ""];
        let scan_cfg = default_config(&[], &[], &[]);
        let result = analyze_line(line, "test.rs", 1, context, None, &scan_cfg);
        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_line_example_context_suppresses() {
        let line = r#"let example_key = "AKIAIOSFODNN7EXAMPLE";"#;
        let prev_line = "// example";
        let context = [prev_line, line, ""];
        let scan_cfg = default_config(&[], &[], &[]);
        let result = analyze_line(line, "test.rs", 2, context, None, &scan_cfg);
        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_line_high_entropy() {
        let line = r#"let token = "aB3$kL9mN2pQ5rS7tU1vW4xY6zA8cD0eFgH2iJ4kL6mN8";"#;
        let context = ["", line, ""];
        let disabled = vec!["HARDCODED_PASSWORD".to_string()];
        let scan_cfg = default_config(&disabled, &[], &[]);
        let result = analyze_line(line, "test.rs", 1, context, None, &scan_cfg);
        assert!(result.is_some());
        let sin = result.unwrap();
        assert_eq!(sin.rule_id, "HIGH_ENTROPY");
    }

    #[test]
    fn test_analyze_context_example_var_pattern() {
        assert!(analyze_context(
            &[],
            r#"let test_key = "value";"#,
            Some("value"),
            "test.rs",
        ));
        assert!(analyze_context(
            &[],
            r#"const example_token = "abc";"#,
            Some("abc"),
            "test.rs",
        ));
        assert!(analyze_context(
            &[],
            r#"var fake_secret = "123";"#,
            Some("123"),
            "test.rs",
        ));
    }

    #[test]
    fn test_analyze_context_example_value_pattern() {
        assert!(analyze_context(
            &[],
            "let key = x;",
            Some("example123"),
            "test.rs"
        ));
        assert!(analyze_context(
            &[],
            "let key = x;",
            Some("test-1"),
            "test.rs"
        ));
        assert!(analyze_context(
            &[],
            "let key = x;",
            Some("placeholder"),
            "test.rs"
        ));
        assert!(analyze_context(
            &[],
            "let key = x;",
            Some("demo_99"),
            "test.rs"
        ));
    }

    #[test]
    fn test_analyze_context_comment_pattern() {
        assert!(analyze_context(
            &["// example config"],
            "let key = x;",
            None,
            "test.rs",
        ));
        assert!(analyze_context(
            &["# test value"],
            "let key = x;",
            None,
            "test.rs"
        ));
        assert!(analyze_context(
            &["example:"],
            "let key = x;",
            None,
            "test.rs"
        ));
    }

    #[test]
    fn test_analyze_context_no_match() {
        assert!(!analyze_context(
            &[],
            "let key = x;",
            Some("real_secret_123"),
            "src/main.rs",
        ));
        assert!(!analyze_context(
            &["// production config"],
            "let key = x;",
            None,
            "src/main.rs",
        ));
    }

    #[test]
    fn test_analyze_line_disabled_rule() {
        let line = r#"let key = "AKIA0000000000000000";"#;
        let context = ["", line, ""];
        let disabled = vec!["AWS_ACCESS_KEY".to_string()];
        let scan_cfg = default_config(&disabled, &[], &[]);
        let result = analyze_line(line, "test.rs", 1, context, None, &scan_cfg);
        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_line_whitelist() {
        let line = r#"let key = "AKIAIOSFODNN7EXAMPLE";"#;
        let context = ["", line, ""];
        let whitelist = vec!["AKIAIOSFODNN7EXAMPLE".to_string()];
        let scan_cfg = default_config(&[], &whitelist, &[]);
        let result = analyze_line(line, "test.rs", 1, context, None, &scan_cfg);
        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_line_regex_context_skipped() {
        let line = r#"let pattern = Regex::new("aB3kL9mN2pQ5rS7tU1vW4xY6zA8cD0eFgH");"#;
        let context = ["", line, ""];
        let scan_cfg = AnalyzeLineConfig {
            entropy_threshold: 3.5,
            disabled_rules: &[],
            whitelist: &[],
            custom_rules: &[],
            skip_entropy_in_regex_context: true,
            allowlist_regexes: None,
        };
        let result = analyze_line(line, "test.rs", 1, context, None, &scan_cfg);
        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_line_custom_rule() {
        let custom_rule = CompiledCustomRule {
            id: "CUSTOM_PATTERN".to_string(),
            pattern: Regex::new(r"MYAPP_[A-Z]{4}_\d{4}").unwrap(),
            description: "Custom app pattern".to_string(),
            severity: Severity::Mortal,
        };
        let line = r#"let config = "MYAPP_XYZW_1234";"#;
        let context = ["", line, ""];
        let custom_rules = vec![custom_rule];
        let scan_cfg = default_config(&[], &[], &custom_rules);
        let result = analyze_line(line, "test.rs", 1, context, None, &scan_cfg);
        assert!(result.is_some());
        let sin = result.unwrap();
        assert_eq!(sin.rule_id, "CUSTOM_PATTERN");
    }

    #[test]
    fn test_analyze_line_github_token() {
        let line = r#"const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";"#;
        let context = ["", line, ""];
        let scan_cfg = default_config(&[], &[], &[]);
        let result = analyze_line(line, "test.rs", 1, context, None, &scan_cfg);
        assert!(result.is_some());
        let sin = result.unwrap();
        assert_eq!(sin.rule_id, "GITHUB_TOKEN");
    }

    #[test]
    fn test_analyze_line_commit_hash_preserved() {
        let line = r#"let key = "AKIA0000000000000000";"#;
        let context = ["", line, ""];
        let scan_cfg = default_config(&[], &[], &[]);
        let commit = Some("abc123def".to_string());
        let result = analyze_line(line, "test.rs", 1, context, commit.clone(), &scan_cfg);
        assert!(result.is_some());
        let sin = result.unwrap();
        assert_eq!(sin.commit_hash, commit);
    }

    #[test]
    fn test_is_regex_context() {
        assert!(is_regex_context(r#"Regex::new("pattern")"#));
        assert!(is_regex_context(r"define_regex!(FOO)"));
        assert!(is_regex_context(r#"pattern: r"\d+""#));
        assert!(is_regex_context(r#"re.compile(r"\w+")"#));
        assert!(is_regex_context(r#"new RegExp("test")"#));
        assert!(is_regex_context(r#"let r = regex("abc");"#));
        assert!(is_regex_context(r"// (?i)case insensitive"));
        assert!(!is_regex_context(r"let x = 42;"));
    }

    #[test]
    fn test_is_whitelisted() {
        let whitelist = vec!["allowed_secret".to_string(), "EXAMPLE".to_string()];
        assert!(is_whitelisted("allowed_secret_123", &whitelist));
        assert!(is_whitelisted("AKIAEXAMPLE", &whitelist));
        assert!(!is_whitelisted("real_secret", &whitelist));
    }
}
