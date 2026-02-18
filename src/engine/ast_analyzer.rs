//! AST-aware scope analysis for false-positive filtering.
//!
//! Detects when a finding occurs inside:
//! - A test function (Python `def test_*`, Rust `#[test]`, JS `it/test/describe`, Go `func Test*`)
//! - A comment line (single-line or block)
//! - A docstring / `JSDoc` block
//! - A test file (by path pattern)
//!
//! Used by the scanner to reduce false positives by ~40%.

use std::sync::LazyLock;

use regex::Regex;

// ── Compiled patterns ──────────────────────────────────────────────────────

static PYTHON_DEF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[ \t]*(?:async[ \t]+)?def[ \t]+(\w+)").unwrap());

static RUST_FN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:async[ \t]+)?fn[ \t]+\w+").unwrap()
});

static RUST_TEST_ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[ \t]*#\s*\[(?:tokio::)?test(?:[ \t]*\]|,)").unwrap());

static JS_TEST_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[ \t]*(?:it|test|describe|suite|context|specify|beforeEach|afterEach|beforeAll|afterAll)[ \t]*\(",
    )
    .unwrap()
});

static GO_TEST_FN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^func[ \t]+Test\w*[ \t]*\(").unwrap());

static JAVA_TEST_ANNOTATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[ \t]*@(?:Test|Before|After|BeforeClass|AfterClass|BeforeEach|AfterEach|ParameterizedTest)")
        .unwrap()
});

static RUBY_TEST_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^[ \t]*(?:def[ \t]+test_|it[ \t]*["']|describe[ \t]*["']|context[ \t]*["'])"#)
        .unwrap()
});

static PYTHON_TRIPLE_DOUBLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"""""#).unwrap());

static PYTHON_TRIPLE_SINGLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"'''").unwrap());

// ── Public API ─────────────────────────────────────────────────────────────

/// Detailed scope context for a given line.
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct ScopeContext {
    pub in_test_function: bool,
    pub in_comment: bool,
    pub in_docstring: bool,
    pub is_test_file: bool,
}

/// Returns `true` if the finding at `line_idx` should be suppressed.
///
/// Suppresses findings in:
/// - Test functions (`def test_*`, `#[test]`, `it(...)`, etc.)
/// - Docstrings / `JSDoc` blocks (typically contain example values)
/// - Test files (by path convention)
///
/// Does **not** suppress standalone comment lines — comments may contain real
/// secrets or PII that must be reported (e.g. `# CPF: 529.982.247-25`).
/// Comments inside test functions are still suppressed via `in_test_function`.
#[must_use]
pub fn should_filter_finding(path: &str, lines: &[&str], line_idx: usize) -> bool {
    let ctx = analyze_scope(path, lines, line_idx);
    ctx.in_docstring || ctx.in_test_function || ctx.is_test_file
}

/// Full scope analysis for a line.
#[must_use]
pub fn analyze_scope(path: &str, lines: &[&str], line_idx: usize) -> ScopeContext {
    let ext = get_extension(path).to_lowercase();
    ScopeContext {
        is_test_file: is_test_file(path),
        in_comment: is_in_comment(lines, line_idx, &ext),
        in_docstring: is_in_docstring(lines, line_idx, &ext),
        in_test_function: is_in_test_function(lines, line_idx, &ext),
    }
}

// ── Test file detection ────────────────────────────────────────────────────

pub(crate) fn is_test_file(path: &str) -> bool {
    let p = path.replace('\\', "/");
    let lower = p.to_lowercase();

    if lower.contains("/tests/")
        || lower.starts_with("tests/")
        || lower.contains("/test/")
        || lower.starts_with("test/")
        || lower.contains("/__tests__/")
        || lower.starts_with("__tests__/")
        || lower.contains("/spec/")
        || lower.starts_with("spec/")
        || lower.contains("/testdata/")
        || lower.contains("/test_data/")
        || lower.contains("/fixtures/")
    {
        return true;
    }

    let filename = p.rsplit('/').next().unwrap_or(&p).to_lowercase();
    filename.starts_with("test_")
        || filename.ends_with("_test.py")
        || filename.ends_with("_test.rs")
        || filename.ends_with("_test.go")
        || filename.ends_with("_spec.rb")
        || filename.ends_with(".spec.js")
        || filename.ends_with(".spec.ts")
        || filename.ends_with(".spec.jsx")
        || filename.ends_with(".spec.tsx")
        || filename.ends_with(".test.js")
        || filename.ends_with(".test.ts")
        || filename.ends_with(".test.jsx")
        || filename.ends_with(".test.tsx")
        || filename == "conftest.py"
        || filename == "fixtures.py"
}

// ── Comment detection ──────────────────────────────────────────────────────

fn is_in_comment(lines: &[&str], line_idx: usize, ext: &str) -> bool {
    let Some(line) = lines.get(line_idx) else {
        return false;
    };
    let trimmed = line.trim_start();

    match ext {
        "py" | "rb" | "sh" | "bash" | "zsh" | "yaml" | "yml" | "toml" | "r" => {
            trimmed.starts_with('#')
        }
        "rs" | "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" | "go" | "java" | "kt" | "cs" | "c"
        | "cpp" | "h" | "hpp" | "swift" | "scala" => {
            if trimmed.starts_with("//") {
                return true;
            }
            is_in_block_comment(lines, line_idx)
        }
        "html" | "xml" | "svg" => {
            trimmed.starts_with("<!--") || is_in_html_comment(lines, line_idx)
        }
        _ => trimmed.starts_with('#') || trimmed.starts_with("//"),
    }
}

fn is_in_block_comment(lines: &[&str], line_idx: usize) -> bool {
    // A line inside `/* ... */`. We scan from the beginning counting delimiters.
    let mut depth = 0i32;
    for (i, line) in lines.iter().enumerate().take(line_idx + 1) {
        // Scan character pairs to find /* and */
        let bytes = line.as_bytes();
        let mut j = 0;
        while j + 1 < bytes.len() {
            if bytes[j] == b'/' && bytes[j + 1] == b'*' {
                depth += 1;
                j += 2;
                continue;
            }
            if bytes[j] == b'*' && bytes[j + 1] == b'/' {
                depth -= 1;
                j += 2;
                continue;
            }
            j += 1;
        }

        if i == line_idx {
            // Also treat lines that start with ` * ` (JSDoc-style) as inside block comment
            let trimmed = line.trim_start();
            if depth > 0 || trimmed.starts_with("* ") || trimmed == "*" || trimmed.starts_with("*/")
            {
                return depth > 0 || trimmed.starts_with("* ") || trimmed == "*";
            }
        }
    }
    false
}

fn is_in_html_comment(lines: &[&str], line_idx: usize) -> bool {
    let mut in_comment = false;
    for (i, line) in lines.iter().enumerate().take(line_idx + 1) {
        if line.contains("<!--") {
            in_comment = true;
        }
        if line.contains("-->") && i < line_idx {
            in_comment = false;
        }
    }
    in_comment
}

// ── Docstring detection ────────────────────────────────────────────────────

fn is_in_docstring(lines: &[&str], line_idx: usize, ext: &str) -> bool {
    match ext {
        "py" => is_in_python_docstring(lines, line_idx),
        "js" | "ts" | "jsx" | "tsx" | "mjs" | "java" | "kt" | "cs" | "go" | "rs" | "scala" => {
            is_in_jsdoc_block(lines, line_idx)
        }
        _ => false,
    }
}

/// Detect Python triple-quoted strings (`"""` or `'''`).
fn is_in_python_docstring(lines: &[&str], line_idx: usize) -> bool {
    let mut in_double = false;
    let mut in_single = false;

    for (i, line) in lines.iter().enumerate().take(line_idx + 1) {
        // Count triple-quote occurrences (even number = balanced on this line)
        let double_count = PYTHON_TRIPLE_DOUBLE.find_iter(line).count();
        let single_count = PYTHON_TRIPLE_SINGLE.find_iter(line).count();

        for _ in 0..double_count {
            in_double = !in_double;
        }
        for _ in 0..single_count {
            in_single = !in_single;
        }

        if i == line_idx {
            return in_double || in_single;
        }
    }
    false
}

/// Detect `JSDoc`/`/** ... */` block comments.
fn is_in_jsdoc_block(lines: &[&str], line_idx: usize) -> bool {
    let mut in_jsdoc = false;
    for (i, line) in lines.iter().enumerate().take(line_idx + 1) {
        let trimmed = line.trim_start();
        if trimmed.starts_with("/**") || trimmed.starts_with("/*!") {
            in_jsdoc = true;
        }
        if trimmed.contains("*/") && i < line_idx {
            in_jsdoc = false;
        }
        if i == line_idx {
            return in_jsdoc;
        }
    }
    false
}

// ── Test function detection ────────────────────────────────────────────────

fn is_in_test_function(lines: &[&str], line_idx: usize, ext: &str) -> bool {
    match ext {
        "py" => is_in_python_test_fn(lines, line_idx),
        "rs" => is_in_rust_test_fn(lines, line_idx),
        "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" => is_in_js_test_fn(lines, line_idx),
        "go" => is_in_go_test_fn(lines, line_idx),
        "java" | "kt" => is_in_java_test_fn(lines, line_idx),
        "rb" => is_in_ruby_test_fn_scope(lines, line_idx),
        _ => false,
    }
}

/// Python: scan backwards for enclosing `def`, check if it is test-related.
fn is_in_python_test_fn(lines: &[&str], line_idx: usize) -> bool {
    if line_idx == 0 {
        return false;
    }
    let current_indent = indent_level(lines[line_idx]);

    for i in (0..line_idx).rev() {
        let line = lines[i];
        if line.trim().is_empty() {
            continue;
        }
        let ind = indent_level(line);

        // Enclosing function: indentation strictly less than current line
        if ind < current_indent {
            if let Some(caps) = PYTHON_DEF.captures(line) {
                let name = caps.get(1).map_or("", |m| m.as_str());
                return name.starts_with("test_")
                    || matches!(
                        name,
                        "setUp"
                            | "tearDown"
                            | "setUpClass"
                            | "tearDownClass"
                            | "setUpTestData"
                            | "asyncSetUp"
                            | "asyncTearDown"
                    );
            }
        }

        // Top-level def (indent 0) — this is the outermost scope
        if ind == 0 {
            if let Some(caps) = PYTHON_DEF.captures(line) {
                let name = caps.get(1).map_or("", |m| m.as_str());
                return name.starts_with("test_");
            }
            break;
        }
    }
    false
}

/// Rust: look backward for `#[test]` attribute on an enclosing `fn`, or `mod tests`.
fn is_in_rust_test_fn(lines: &[&str], line_idx: usize) -> bool {
    let scan_start = line_idx.saturating_sub(300);
    let mut brace_depth = 0i32;

    for i in (scan_start..=line_idx).rev() {
        let line = lines[i];

        for ch in line.chars().rev() {
            match ch {
                '}' => brace_depth += 1,
                '{' => brace_depth -= 1,
                _ => {}
            }
        }

        // brace_depth < 0 means we've counted more `{` than `}` backwards
        // → we are inside the block that opens at line `i`
        if brace_depth < 0 {
            let trimmed = line.trim();

            // `mod tests { ... }` or `mod test_* { ... }`
            if trimmed.contains("mod tests") || trimmed.contains("mod test_") {
                return true;
            }

            // `fn` declaration — look backward for `#[test]`
            if RUST_FN.is_match(line) {
                for j in (scan_start..i).rev().take(10) {
                    let prev = lines[j].trim();
                    if prev.is_empty() {
                        continue;
                    }
                    if RUST_TEST_ATTR.is_match(lines[j]) {
                        return true;
                    }
                    // Stop if we hit something other than attributes / comments
                    if !prev.starts_with('#') && !prev.starts_with("//") {
                        break;
                    }
                }
            }

            brace_depth = 0; // reset and continue searching outer scope
        }
    }
    false
}

/// JavaScript/TypeScript: detect `it(`, `test(`, `describe(` scope.
fn is_in_js_test_fn(lines: &[&str], line_idx: usize) -> bool {
    let scan_start = line_idx.saturating_sub(200);
    let mut paren_brace_depth = 0i32;

    for i in (scan_start..=line_idx).rev() {
        let line = lines[i];

        for ch in line.chars().rev() {
            match ch {
                '}' | ')' => paren_brace_depth += 1,
                '{' | '(' => paren_brace_depth -= 1,
                _ => {}
            }
        }

        if paren_brace_depth < 0 && JS_TEST_CALL.is_match(line) {
            return true;
        }
    }
    false
}

/// Go: look for enclosing `func Test*`.
fn is_in_go_test_fn(lines: &[&str], line_idx: usize) -> bool {
    let scan_start = line_idx.saturating_sub(200);
    let mut brace_depth = 0i32;

    for i in (scan_start..=line_idx).rev() {
        let line = lines[i];

        for ch in line.chars().rev() {
            match ch {
                '}' => brace_depth += 1,
                '{' => brace_depth -= 1,
                _ => {}
            }
        }

        if brace_depth < 0 && GO_TEST_FN.is_match(line) {
            return true;
        }
    }
    false
}

/// Java/Kotlin: look for `@Test` annotation on the enclosing method.
fn is_in_java_test_fn(lines: &[&str], line_idx: usize) -> bool {
    let scan_start = line_idx.saturating_sub(200);
    let mut brace_depth = 0i32;

    for i in (scan_start..=line_idx).rev() {
        let line = lines[i];

        for ch in line.chars().rev() {
            match ch {
                '}' => brace_depth += 1,
                '{' => brace_depth -= 1,
                _ => {}
            }
        }

        if brace_depth < 0 {
            // Found opening brace of a method — check preceding lines for @Test
            for j in (scan_start..i).rev().take(5) {
                let prev = lines[j].trim();
                if JAVA_TEST_ANNOTATION.is_match(lines[j]) {
                    return true;
                }
                if !prev.starts_with('@') && !prev.is_empty() {
                    break;
                }
            }
            brace_depth = 0;
        }
    }
    false
}

/// Ruby: detect `def test_*` or `it "..."` enclosing scope.
fn is_in_ruby_test_fn_scope(lines: &[&str], line_idx: usize) -> bool {
    let scan_start = line_idx.saturating_sub(100);
    let current_indent = indent_level(lines[line_idx]);

    for i in (scan_start..line_idx).rev() {
        let line = lines[i];
        if line.trim().is_empty() {
            continue;
        }
        if indent_level(line) < current_indent && RUBY_TEST_METHOD.is_match(line) {
            return true;
        }
        // Stop at `end` at lower indentation
        if line.trim() == "end" && indent_level(line) < current_indent {
            break;
        }
    }
    false
}

// ── Utilities ──────────────────────────────────────────────────────────────

fn get_extension(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or("")
}

fn indent_level(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_test_file ──────────────────────────────────────────────────────

    #[test]
    fn test_is_test_file_dirs() {
        assert!(is_test_file("project/tests/auth.py"));
        assert!(is_test_file("project/test/auth.py"));
        assert!(is_test_file("src/__tests__/auth.test.ts"));
        assert!(is_test_file("spec/models/user_spec.rb"));
    }

    #[test]
    fn test_is_test_file_names() {
        assert!(is_test_file("test_auth.py"));
        assert!(is_test_file("auth_test.go"));
        assert!(is_test_file("auth.spec.ts"));
        assert!(is_test_file("auth.test.tsx"));
        assert!(!is_test_file("src/auth.py"));
        assert!(!is_test_file("src/main.rs"));
    }

    // ── comment detection ─────────────────────────────────────────────────

    #[test]
    fn test_python_comment() {
        let lines = vec!["# AWS_ACCESS_KEY = \"AKIA1234567890ABCDEF\""];
        assert!(is_in_comment(&lines, 0, "py"));
    }

    #[test]
    fn test_rust_line_comment() {
        let lines = vec!["    // let key = \"AKIA1234567890ABCDEF\";"];
        assert!(is_in_comment(&lines, 0, "rs"));
    }

    #[test]
    fn test_non_comment_not_filtered() {
        let lines = vec!["let key = \"AKIA1234567890ABCDEF\";"];
        assert!(!is_in_comment(&lines, 0, "rs"));
    }

    // ── docstring detection ───────────────────────────────────────────────

    #[test]
    fn test_python_docstring_inside() {
        let lines = vec![
            "def validate():",
            "    \"\"\"",
            "    Example: key = \"AKIA1234567890ABCDEF\"",
            "    \"\"\"",
            "    pass",
        ];
        assert!(is_in_python_docstring(&lines, 2));
        assert!(!is_in_python_docstring(&lines, 4));
    }

    #[test]
    fn test_jsdoc_block() {
        let lines = vec![
            "/**",
            " * @param key - \"AKIA1234567890ABCDEF\" example",
            " */",
            "function validate(key) {}",
        ];
        assert!(is_in_jsdoc_block(&lines, 1));
        assert!(!is_in_jsdoc_block(&lines, 3));
    }

    // ── test function detection ───────────────────────────────────────────

    #[test]
    fn test_python_test_fn() {
        let lines = vec![
            "def test_validate_key():",
            "    key = \"AKIA1234567890ABCDEF\"",
            "    assert validate(key)",
        ];
        assert!(is_in_python_test_fn(&lines, 1));
        assert!(is_in_python_test_fn(&lines, 2));
    }

    #[test]
    fn test_python_non_test_fn_not_filtered() {
        let lines = vec!["def get_key():", "    return \"AKIA1234567890ABCDEF\""];
        assert!(!is_in_python_test_fn(&lines, 1));
    }

    #[test]
    fn test_rust_test_module() {
        let lines = vec![
            "#[cfg(test)]",
            "mod tests {",
            "    #[test]",
            "    fn test_aws() {",
            "        let key = \"AKIA1234567890ABCDEF\";",
            "    }",
            "}",
        ];
        assert!(is_in_rust_test_fn(&lines, 4));
    }

    #[test]
    fn test_rust_non_test_fn() {
        let lines = vec![
            "fn get_key() -> &str {",
            "    \"AKIA1234567890ABCDEF\"",
            "}",
        ];
        assert!(!is_in_rust_test_fn(&lines, 1));
    }

    #[test]
    fn test_js_test_fn() {
        let lines = vec![
            "describe('auth', () => {",
            "  it('validates key', () => {",
            "    const key = 'AKIA1234567890ABCDEF';",
            "    expect(validate(key)).toBe(true);",
            "  });",
            "});",
        ];
        assert!(is_in_js_test_fn(&lines, 2));
        assert!(is_in_js_test_fn(&lines, 3));
    }

    // ── should_filter_finding ─────────────────────────────────────────────

    #[test]
    fn test_filter_python_test_fn() {
        let lines = vec!["def test_auth():", "    key = \"AKIA1234567890ABCDEF\""];
        assert!(should_filter_finding("src/auth.py", &lines, 1));
    }

    #[test]
    fn test_filter_test_file() {
        let lines = vec!["key = \"AKIA1234567890ABCDEF\""];
        assert!(should_filter_finding("tests/auth.py", &lines, 0));
    }

    #[test]
    fn test_comment_line_not_filtered_standalone() {
        // Comments in production files are NOT filtered — they may contain real secrets
        let lines = vec!["# key = \"AKIA1234567890ABCDEF\""];
        assert!(!should_filter_finding("src/auth.py", &lines, 0));
    }

    #[test]
    fn test_no_filter_production_code() {
        let lines = vec!["key = \"AKIA1234567890ABCDEF\""];
        assert!(!should_filter_finding("src/auth.py", &lines, 0));
    }
}
