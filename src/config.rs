use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct VelkaConfig {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_ignore_paths")]
    pub ignore_paths: Vec<String>,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub disable: Vec<String>,
}

fn default_ignore_paths() -> Vec<String> {
    vec![
        "**/target/**".to_string(),
        "**/.git/**".to_string(),
        "**/node_modules/**".to_string(),
        "**/*.lock".to_string(),
        "**/*.png".to_string(),
        "**/*.jpg".to_string(),
    ]
}

fn default_entropy_threshold() -> f32 {
    4.6
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            ignore_paths: default_ignore_paths(),
            entropy_threshold: default_entropy_threshold(),
        }
    }
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            disable: Vec::new(),
        }
    }
}

impl Default for VelkaConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            rules: RulesConfig::default(),
        }
    }
}

impl VelkaConfig {
    pub fn load() -> Result<Self> {
        let config_path = std::path::Path::new("velka.toml");
        
        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(config_path)
            .context("Failed to read velka.toml")?;

        let config: VelkaConfig = toml::from_str(&content)
            .context("Failed to parse velka.toml")?;

        Ok(config)
    }
}
