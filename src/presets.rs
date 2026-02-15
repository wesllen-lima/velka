pub const PRESET_STRICT: &str = r#"[scan]
ignore_paths = []
entropy_threshold = 4.0
max_file_size_mb = 100
skip_minified_threshold = 10000

[output]
redact_secrets = true
redact_visible_chars = 4

[cache]
enabled = true
location = "both"

[rules]
disable = []
"#;

pub const PRESET_BALANCED: &str = r#"[scan]
ignore_paths = [
  "tests/**",
  "docs/**",
  "examples/**",
  "vendor/**",
]
entropy_threshold = 4.6
max_file_size_mb = 50
skip_minified_threshold = 10000

[output]
redact_secrets = true
redact_visible_chars = 4

[cache]
enabled = true
location = "both"

[rules]
disable = []
"#;

pub const PRESET_CI: &str = r#"[scan]
ignore_paths = [
  "tests/**",
  "examples/**",
  "vendor/**",
]
entropy_threshold = 4.6
max_file_size_mb = 50
skip_minified_threshold = 10000

[output]
redact_secrets = true
redact_visible_chars = 4

[cache]
enabled = false
location = "both"

[rules]
disable = []
"#;

pub const PRESET_MONOREPO: &str = r#"[scan]
ignore_paths = [
  "dist/**",
  "build/**",
  ".next/**",
  "coverage/**",
  "node_modules/**",
  "vendor/**",
]
entropy_threshold = 4.6
max_file_size_mb = 80
skip_minified_threshold = 12000

[output]
redact_secrets = true
redact_visible_chars = 4

[cache]
enabled = true
location = "both"

[rules]
disable = []
"#;
