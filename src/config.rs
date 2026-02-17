use std::collections::HashMap;

use regex::Regex;
use serde::Deserialize;

use crate::domain::Severity;
use crate::engine::CompiledCustomRule;
use crate::error::{Result, VelkaError};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct VelkaConfig {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileOverrides>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub file_patterns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_ignore_paths")]
    pub ignore_paths: Vec<String>,
    #[serde(default)]
    pub allowlist: Option<AllowlistConfig>,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f32,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default = "default_max_file_size")]
    pub max_file_size_mb: u64,
    #[serde(default = "default_minified_threshold")]
    pub skip_minified_threshold: usize,
    #[serde(default = "default_entropy_skip_regex_context")]
    pub entropy_skip_regex_context: bool,
    #[serde(default = "default_streaming_threshold")]
    pub streaming_threshold_mb: u64,
    #[serde(default)]
    pub verify: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_true")]
    pub redact_secrets: bool,
    #[serde(default = "default_visible_chars")]
    pub redact_visible_chars: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub location: CacheLocation,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CacheLocation {
    Project,
    User,
    #[default]
    Both,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RulesConfig {
    #[serde(default)]
    pub disable: Vec<String>,
    #[serde(default)]
    pub custom: Vec<CustomRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub pattern: String,
    pub severity: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProfileOverrides {
    #[serde(default)]
    pub scan: Option<PartialScanConfig>,
    #[serde(default)]
    pub output: Option<PartialOutputConfig>,
    #[serde(default)]
    pub cache: Option<PartialCacheConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PartialScanConfig {
    pub entropy_threshold: Option<f32>,
    pub whitelist: Option<Vec<String>>,
    pub max_file_size_mb: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PartialOutputConfig {
    pub redact_secrets: Option<bool>,
    pub redact_visible_chars: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PartialCacheConfig {
    pub enabled: Option<bool>,
    pub location: Option<CacheLocation>,
}

fn default_true() -> bool {
    true
}

fn default_visible_chars() -> usize {
    4
}

fn default_max_file_size() -> u64 {
    50
}

fn default_minified_threshold() -> usize {
    10_000
}

fn default_ignore_paths() -> Vec<String> {
    vec![
        "**/target/**".to_string(),
        "**/.git/**".to_string(),
        "**/node_modules/**".to_string(),
        "**/*.lock".to_string(),
        "**/*.png".to_string(),
        "**/*.jpg".to_string(),
        "**/*.jpeg".to_string(),
        "**/*.gif".to_string(),
        "**/*.ico".to_string(),
        "**/*.woff".to_string(),
        "**/*.woff2".to_string(),
        "**/*.ttf".to_string(),
        "**/*.eot".to_string(),
        "**/*.mp3".to_string(),
        "**/*.mp4".to_string(),
        "**/*.webm".to_string(),
        "**/*.zip".to_string(),
        "**/*.tar".to_string(),
        "**/*.gz".to_string(),
        "**/*.rar".to_string(),
        "**/*.7z".to_string(),
        "**/*.pdf".to_string(),
        "**/*.min.js".to_string(),
        "**/*.min.css".to_string(),
        "**/.velka-cache/**".to_string(),
    ]
}

fn default_entropy_threshold() -> f32 {
    4.6
}

fn default_entropy_skip_regex_context() -> bool {
    true
}

fn default_streaming_threshold() -> u64 {
    10
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            ignore_paths: default_ignore_paths(),
            allowlist: None,
            entropy_threshold: default_entropy_threshold(),
            whitelist: Vec::new(),
            max_file_size_mb: default_max_file_size(),
            skip_minified_threshold: default_minified_threshold(),
            entropy_skip_regex_context: default_entropy_skip_regex_context(),
            streaming_threshold_mb: default_streaming_threshold(),
            verify: false,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            redact_secrets: default_true(),
            redact_visible_chars: default_visible_chars(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            location: CacheLocation::default(),
        }
    }
}

impl VelkaConfig {
    pub fn load() -> Result<Self> {
        let config_path = std::path::Path::new("velka.toml");
        if !config_path.exists() {
            return Ok(Self::default());
        }
        Self::load_from(config_path)
    }

    pub fn load_from(config_path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(config_path)?;
        let config: VelkaConfig =
            toml::from_str(&content).map_err(|e| VelkaError::Toml(e.to_string()))?;
        compile_allowlist_regexes(config.scan.allowlist.as_ref())?;
        compile_allowlist_file_patterns(config.scan.allowlist.as_ref())?;
        Ok(config)
    }

    #[must_use]
    pub fn with_profile(mut self, profile_name: &str) -> Self {
        if let Some(overrides) = self.profiles.get(profile_name).cloned() {
            if let Some(scan) = overrides.scan {
                if let Some(v) = scan.entropy_threshold {
                    self.scan.entropy_threshold = v;
                }
                if let Some(v) = scan.whitelist {
                    self.scan.whitelist = v;
                }
                if let Some(v) = scan.max_file_size_mb {
                    self.scan.max_file_size_mb = v;
                }
            }
            if let Some(output) = overrides.output {
                if let Some(v) = output.redact_secrets {
                    self.output.redact_secrets = v;
                }
                if let Some(v) = output.redact_visible_chars {
                    self.output.redact_visible_chars = v;
                }
            }
            if let Some(cache) = overrides.cache {
                if let Some(v) = cache.enabled {
                    self.cache.enabled = v;
                }
                if let Some(v) = cache.location {
                    self.cache.location = v;
                }
            }
        }
        self
    }

    pub fn compile_custom_rules(&self) -> Result<Vec<CompiledCustomRule>> {
        self.rules
            .custom
            .iter()
            .map(|rule| {
                let pattern =
                    Regex::new(&rule.pattern).map_err(|e| VelkaError::InvalidPattern {
                        rule_id: rule.id.clone(),
                        message: e.to_string(),
                    })?;

                let severity = match rule.severity.to_lowercase().as_str() {
                    "mortal" => Severity::Mortal,
                    "venial" => Severity::Venial,
                    _ => {
                        return Err(VelkaError::InvalidPattern {
                            rule_id: rule.id.clone(),
                            message: format!(
                                "Invalid severity '{}'. Must be 'Mortal' or 'Venial'",
                                rule.severity
                            ),
                        });
                    }
                };

                Ok(CompiledCustomRule {
                    id: rule.id.clone(),
                    pattern,
                    severity,
                    description: rule
                        .description
                        .clone()
                        .unwrap_or_else(|| format!("Custom rule: {}", rule.id)),
                })
            })
            .collect()
    }
}

pub fn compile_allowlist_regexes(allowlist: Option<&AllowlistConfig>) -> Result<Vec<Regex>> {
    let Some(list) = allowlist else {
        return Ok(Vec::new());
    };
    list.regexes
        .iter()
        .map(|s| Regex::new(s).map_err(|e| VelkaError::Config(e.to_string())))
        .collect()
}

pub fn compile_allowlist_file_patterns(allowlist: Option<&AllowlistConfig>) -> Result<Vec<Regex>> {
    let Some(list) = allowlist else {
        return Ok(Vec::new());
    };
    list.file_patterns
        .iter()
        .map(|s| Regex::new(s).map_err(|e| VelkaError::Config(e.to_string())))
        .collect()
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = VelkaConfig::default();
        assert_eq!(config.scan.entropy_threshold, 4.6);
        assert!(config
            .scan
            .ignore_paths
            .contains(&"**/target/**".to_string()));
        assert!(config.output.redact_secrets);
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_load_from_valid_toml() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("velka.toml");
        std::fs::write(
            &config_path,
            r#"
[scan]
entropy_threshold = 5.0
whitelist = ["example.com"]

[profile.ci]
cache.enabled = false
"#,
        )
        .unwrap();
        let content = std::fs::read_to_string(&config_path).unwrap();
        let config: VelkaConfig = toml::from_str(&content).unwrap();
        assert_eq!(config.scan.entropy_threshold, 5.0);
        assert_eq!(config.scan.whitelist, vec!["example.com"]);
    }

    #[test]
    fn test_load_from_fails_on_invalid_allowlist_regex() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("velka.toml");
        std::fs::write(
            &config_path,
            r#"
[scan.allowlist]
regexes = ["[invalid"]
"#,
        )
        .unwrap();
        let result = VelkaConfig::load_from(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_fails_on_invalid_allowlist_file_patterns() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("velka.toml");
        std::fs::write(
            &config_path,
            r#"
[scan.allowlist]
file_patterns = ["(?invalid"]
"#,
        )
        .unwrap();
        let result = VelkaConfig::load_from(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_with_profile_applies_overrides() {
        let mut config = VelkaConfig::default();
        config.profiles.insert(
            "ci".to_string(),
            ProfileOverrides {
                scan: None,
                output: Some(PartialOutputConfig {
                    redact_secrets: Some(true),
                    redact_visible_chars: Some(8),
                }),
                cache: Some(PartialCacheConfig {
                    enabled: Some(false),
                    location: None,
                }),
            },
        );
        config = config.with_profile("ci");
        assert!(!config.cache.enabled);
        assert_eq!(config.output.redact_visible_chars, 8);
    }

    #[test]
    fn test_with_profile_unknown_no_change() {
        let config = VelkaConfig::default();
        let after = config.clone().with_profile("nonexistent");
        assert_eq!(after.scan.entropy_threshold, config.scan.entropy_threshold);
    }

    #[test]
    fn test_compile_custom_rules_valid() {
        let mut config = VelkaConfig::default();
        config.rules.custom.push(CustomRule {
            id: "TEST_RULE".to_string(),
            pattern: r"\d{5}".to_string(),
            severity: "Mortal".to_string(),
            description: Some("Test".to_string()),
        });
        let compiled = config.compile_custom_rules();
        assert!(compiled.is_ok());
        let rules = compiled.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "TEST_RULE");
    }

    #[test]
    fn test_compile_custom_rules_invalid_regex() {
        let mut config = VelkaConfig::default();
        config.rules.custom.push(CustomRule {
            id: "BAD".to_string(),
            pattern: "[invalid".to_string(),
            severity: "Mortal".to_string(),
            description: None,
        });
        let result = config.compile_custom_rules();
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_custom_rules_invalid_severity() {
        let mut config = VelkaConfig::default();
        config.rules.custom.push(CustomRule {
            id: "BAD".to_string(),
            pattern: r"\d+".to_string(),
            severity: "Critical".to_string(),
            description: None,
        });
        let result = config.compile_custom_rules();
        assert!(result.is_err());
    }
}
