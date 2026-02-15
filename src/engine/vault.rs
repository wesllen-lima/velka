use anyhow::Result;

/// A secret ready to be uploaded to a vault provider.
#[derive(Debug, Clone)]
pub struct VaultSecret {
    pub key: String,
    pub value: String,
    pub metadata: VaultMetadata,
}

#[derive(Debug, Clone, Default)]
pub struct VaultMetadata {
    pub source_file: String,
    pub rule_id: String,
    pub detected_at: String,
}

/// Result of a vault sync operation.
#[derive(Debug)]
pub struct SyncResult {
    pub provider: String,
    pub path: String,
    pub success: bool,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

pub trait VaultProvider: Send + Sync {
    fn name(&self) -> &str;
    fn store(&self, path: &str, secret: &VaultSecret) -> Result<SyncResult>;
    fn check_connection(&self) -> Result<bool>;
}

// ---------------------------------------------------------------------------
// HashiCorp Vault
// ---------------------------------------------------------------------------

pub struct HashiCorpVault {
    pub addr: String,
    pub token: String,
    pub mount: String,
}

impl HashiCorpVault {
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let addr = std::env::var("VAULT_ADDR").ok()?;
        let token = std::env::var("VAULT_TOKEN").ok()?;
        let mount = std::env::var("VAULT_MOUNT").unwrap_or_else(|_| "secret".to_string());
        Some(Self { addr, token, mount })
    }
}

impl VaultProvider for HashiCorpVault {
    fn name(&self) -> &'static str {
        "HashiCorp Vault"
    }

    fn store(&self, path: &str, secret: &VaultSecret) -> Result<SyncResult> {
        let url = format!(
            "{}/v1/{}/data/{}",
            self.addr.trim_end_matches('/'),
            self.mount,
            path
        );

        let payload = serde_json::json!({
            "data": {
                &secret.key: &secret.value,
                "_velka_rule": &secret.metadata.rule_id,
                "_velka_source": &secret.metadata.source_file,
            }
        });

        let resp = reqwest::blocking::Client::new()
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()?;

        let success = resp.status().is_success();
        let message = if success {
            format!("Stored at {}/{}", self.mount, path)
        } else {
            format!("HTTP {}", resp.status())
        };

        Ok(SyncResult {
            provider: self.name().to_string(),
            path: path.to_string(),
            success,
            message,
        })
    }

    fn check_connection(&self) -> Result<bool> {
        let url = format!("{}/v1/sys/health", self.addr.trim_end_matches('/'));
        let resp = reqwest::blocking::Client::new()
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        Ok(resp.status().is_success())
    }
}

// ---------------------------------------------------------------------------
// 1Password (CLI-based skeleton)
// ---------------------------------------------------------------------------

pub struct OnePassword {
    pub vault_name: String,
}

impl OnePassword {
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let vault = std::env::var("OP_VAULT").ok()?;
        Some(Self { vault_name: vault })
    }
}

impl VaultProvider for OnePassword {
    fn name(&self) -> &'static str {
        "1Password"
    }

    fn store(&self, path: &str, secret: &VaultSecret) -> Result<SyncResult> {
        // Uses `op` CLI: op item create --category=password --vault=<vault> --title=<path> password=<value>
        let output = std::process::Command::new("op")
            .args([
                "item",
                "create",
                &format!("--vault={}", self.vault_name),
                &format!("--title={path}"),
                "--category=password",
                &format!("password={}", secret.value),
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => Ok(SyncResult {
                provider: self.name().to_string(),
                path: path.to_string(),
                success: true,
                message: format!("Created item '{}' in vault '{}'", path, self.vault_name),
            }),
            Ok(out) => Ok(SyncResult {
                provider: self.name().to_string(),
                path: path.to_string(),
                success: false,
                message: String::from_utf8_lossy(&out.stderr).to_string(),
            }),
            Err(e) => Ok(SyncResult {
                provider: self.name().to_string(),
                path: path.to_string(),
                success: false,
                message: format!("op CLI not found or failed: {e}"),
            }),
        }
    }

    fn check_connection(&self) -> Result<bool> {
        let output = std::process::Command::new("op").args(["whoami"]).output();
        Ok(matches!(output, Ok(o) if o.status.success()))
    }
}

// ---------------------------------------------------------------------------
// Helper: auto-detect available providers
// ---------------------------------------------------------------------------

#[must_use]
pub fn detect_providers() -> Vec<Box<dyn VaultProvider>> {
    let mut providers: Vec<Box<dyn VaultProvider>> = Vec::new();

    if let Some(hc) = HashiCorpVault::from_env() {
        providers.push(Box::new(hc));
    }
    if let Some(op) = OnePassword::from_env() {
        providers.push(Box::new(op));
    }

    providers
}

/// Build a suggested vault path from a Sin's metadata.
#[must_use]
pub fn suggest_vault_path(rule_id: &str, source_file: &str) -> String {
    let file_stem = std::path::Path::new(source_file).file_stem().map_or_else(
        || "unknown".to_string(),
        |s| s.to_string_lossy().to_string(),
    );
    format!("velka/{}/{}", file_stem, rule_id.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suggest_vault_path() {
        let path = suggest_vault_path("AWS_ACCESS_KEY", "src/config/prod.env");
        assert_eq!(path, "velka/prod/aws_access_key");
    }

    #[test]
    fn test_detect_providers_empty() {
        // Without env vars set, should return empty (or whatever is configured)
        let providers = detect_providers();
        // Can't assert exact count since CI may have vars; just ensure no panic
        let _ = providers.len();
    }
}
