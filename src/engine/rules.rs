use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};

use crate::domain::Rule;
use crate::domain::Severity;
use crate::error::{Result, VelkaError};

#[derive(Debug, Clone)]
pub struct CompiledCustomRule {
    pub id: String,
    pub pattern: Regex,
    pub severity: Severity,
    pub description: String,
}

macro_rules! define_regex {
    ($re:literal) => {{
        static PATTERN: LazyLock<Regex> =
            LazyLock::new(|| Regex::new($re).expect("Invalid regex pattern"));
        &PATTERN
    }};
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "AWS_ACCESS_KEY",
        description: "AWS Access Key ID detected",
        pattern: define_regex!(r"AKIA[0-9A-Z]{16}"),
        severity: Severity::Mortal,
        expected_len: Some((20, 20)),
        required_prefix: Some("AKIA"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "AWS_SECRET_KEY",
        description: "AWS Secret Access Key detected",
        pattern: define_regex!(r#"(?i)aws_secret_access_key.*['"][A-Za-z0-9/+=]{40}['"]"#),
        severity: Severity::Mortal,
        expected_len: Some((40, 40)),
        required_prefix: None,
        charset: Some("base64"),
    },
    Rule {
        id: "GOOGLE_API_KEY",
        description: "Google API Key detected",
        pattern: define_regex!(r"AIza[0-9A-Za-z\-_]{35}"),
        severity: Severity::Mortal,
        expected_len: Some((39, 39)),
        required_prefix: Some("AIza"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "GITHUB_TOKEN",
        description: "GitHub Personal Access Token detected",
        pattern: define_regex!(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        severity: Severity::Mortal,
        expected_len: Some((40, 100)),
        required_prefix: Some("gh"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "STRIPE_SECRET",
        description: "Stripe Secret Key detected",
        pattern: define_regex!(r"[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}"),
        severity: Severity::Mortal,
        expected_len: Some((32, 100)),
        required_prefix: Some("sk_"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "PRIVATE_KEY",
        description: "Private Key detected",
        pattern: define_regex!(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) PRIVATE KEY-----"),
        severity: Severity::Mortal,
        expected_len: Some((100, 5000)),
        required_prefix: Some("-----BEGIN"),
        charset: None,
    },
    Rule {
        id: "SLACK_WEBHOOK",
        description: "Slack Webhook URL detected",
        pattern: define_regex!(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
        ),
        severity: Severity::Mortal,
        expected_len: Some((70, 120)),
        required_prefix: Some("https://hooks.slack.com"),
        charset: None,
    },
    Rule {
        id: "SENDGRID_API",
        description: "SendGrid API Key detected",
        pattern: define_regex!(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
        severity: Severity::Mortal,
        expected_len: Some((69, 69)),
        required_prefix: Some("SG."),
        charset: Some("base64"),
    },
    Rule {
        id: "TWILIO_API",
        description: "Twilio API Key detected",
        pattern: define_regex!(r"SK[a-f0-9]{32}"),
        severity: Severity::Mortal,
        expected_len: Some((34, 34)),
        required_prefix: Some("SK"),
        charset: Some("hex"),
    },
    Rule {
        id: "NPM_TOKEN",
        description: "NPM Auth Token detected",
        pattern: define_regex!(r"npm_[A-Za-z0-9]{36}"),
        severity: Severity::Mortal,
        expected_len: Some((40, 40)),
        required_prefix: Some("npm_"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "PYPI_TOKEN",
        description: "PyPI API Token detected",
        pattern: define_regex!(r"pypi-[A-Za-z0-9_-]{60,}"),
        severity: Severity::Mortal,
        expected_len: Some((65, 200)),
        required_prefix: Some("pypi-"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "DISCORD_TOKEN",
        description: "Discord Bot Token detected",
        pattern: define_regex!(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"),
        severity: Severity::Mortal,
        expected_len: Some((59, 80)),
        required_prefix: None,
        charset: Some("base64"),
    },
    Rule {
        id: "TELEGRAM_BOT",
        description: "Telegram Bot Token detected",
        pattern: define_regex!(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
        severity: Severity::Mortal,
        expected_len: Some((44, 46)),
        required_prefix: None,
        charset: Some("alphanum"),
    },
    Rule {
        id: "DB_CONNECTION_STRING",
        description: "Database connection string detected",
        pattern: define_regex!(r"(?i)(postgres|mysql|mongodb|redis|mssql)://[^\s]+"),
        severity: Severity::Mortal,
        expected_len: None,
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "HARDCODED_PASSWORD",
        description: "Hardcoded password detected",
        pattern: define_regex!(r#"(?i)(password|passwd|pwd|secret)\s*[:=]\s*['"][^'"]{8,}['"]"#),
        severity: Severity::Mortal,
        expected_len: Some((8, 200)),
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "AZURE_STORAGE_KEY",
        description: "Azure Storage Account Key detected",
        pattern: define_regex!(
            r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"
        ),
        severity: Severity::Mortal,
        expected_len: Some((88, 88)),
        required_prefix: Some("DefaultEndpointsProtocol"),
        charset: Some("base64"),
    },
    Rule {
        id: "GCP_SERVICE_ACCOUNT",
        description: "GCP Service Account Key detected",
        pattern: define_regex!(r#""type"\s*:\s*"service_account""#),
        severity: Severity::Mortal,
        expected_len: None,
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "HEROKU_API_KEY",
        description: "Heroku API Key detected",
        pattern: define_regex!(
            r"[hH]eroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ),
        severity: Severity::Mortal,
        expected_len: Some((36, 36)),
        required_prefix: None,
        charset: Some("hex"),
    },
    Rule {
        id: "MAILGUN_API_KEY",
        description: "Mailgun API Key detected",
        pattern: define_regex!(r"key-[0-9a-zA-Z]{32}"),
        severity: Severity::Mortal,
        expected_len: Some((36, 36)),
        required_prefix: Some("key-"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "SQUARE_ACCESS_TOKEN",
        description: "Square Access Token detected",
        pattern: define_regex!(r"sq0atp-[0-9A-Za-z\-_]{22}"),
        severity: Severity::Mortal,
        expected_len: Some((29, 29)),
        required_prefix: Some("sq0atp-"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "SQUARE_OAUTH_SECRET",
        description: "Square OAuth Secret detected",
        pattern: define_regex!(r"sq0csp-[0-9A-Za-z\-_]{43}"),
        severity: Severity::Mortal,
        expected_len: Some((50, 50)),
        required_prefix: Some("sq0csp-"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "DATADOG_API_KEY",
        description: "Datadog API Key detected",
        pattern: define_regex!(r#"(?i)datadog.*["'][a-f0-9]{32}["']"#),
        severity: Severity::Mortal,
        expected_len: Some((32, 32)),
        required_prefix: None,
        charset: Some("hex"),
    },
    Rule {
        id: "NEW_RELIC_LICENSE",
        description: "New Relic license key detected",
        pattern: define_regex!(r#"(?i)newrelic.*["'][a-f0-9]{40}["']"#),
        severity: Severity::Mortal,
        expected_len: Some((40, 40)),
        required_prefix: None,
        charset: Some("hex"),
    },
    Rule {
        id: "CLOUDFLARE_API_KEY",
        description: "Cloudflare API key/token detected",
        pattern: define_regex!(r#"(?i)cloudflare.*["'][a-zA-Z0-9_-]{37}["']"#),
        severity: Severity::Mortal,
        expected_len: Some((37, 37)),
        required_prefix: None,
        charset: Some("alphanum"),
    },
    Rule {
        id: "OPENAI_API_KEY",
        description: "OpenAI API key detected",
        pattern: define_regex!(r"sk-[a-zA-Z0-9]{48}"),
        severity: Severity::Mortal,
        expected_len: Some((51, 60)),
        required_prefix: Some("sk-"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "SUPABASE_ANON_KEY",
        description: "Supabase anon/service key detected",
        pattern: define_regex!(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)"),
        severity: Severity::Mortal,
        expected_len: Some((50, 2000)),
        required_prefix: Some("eyJ"),
        charset: Some("base64"),
    },
    Rule {
        id: "VERCEL_TOKEN",
        description: "Vercel API token detected",
        pattern: define_regex!(r#"(?i)vercel.*["'][a-zA-Z0-9_]{24}["']"#),
        severity: Severity::Mortal,
        expected_len: Some((24, 24)),
        required_prefix: None,
        charset: Some("alphanum"),
    },
    Rule {
        id: "MONGODB_ATLAS",
        description: "MongoDB Atlas connection string detected",
        pattern: define_regex!(r"mongodb(\+srv)?://[^\s]+"),
        severity: Severity::Mortal,
        expected_len: None,
        required_prefix: Some("mongodb"),
        charset: None,
    },
    Rule {
        id: "REDIS_URL",
        description: "Redis connection URL detected",
        pattern: define_regex!(r"rediss?://[^\s]+"),
        severity: Severity::Mortal,
        expected_len: None,
        required_prefix: Some("redis"),
        charset: None,
    },
    Rule {
        id: "SENTRY_DSN",
        description: "Sentry DSN detected",
        pattern: define_regex!(r"https://[a-f0-9]+@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+"),
        severity: Severity::Mortal,
        expected_len: None,
        required_prefix: Some("https://"),
        charset: None,
    },
    Rule {
        id: "ALGOLIA_API_KEY",
        description: "Algolia API key detected",
        pattern: define_regex!(r#"(?i)algolia.*["'][a-zA-Z0-9]{32}["']"#),
        severity: Severity::Mortal,
        expected_len: Some((32, 32)),
        required_prefix: None,
        charset: Some("alphanum"),
    },
    Rule {
        id: "NOTION_API_KEY",
        description: "Notion API secret detected",
        pattern: define_regex!(r"secret_[a-zA-Z0-9]{32}"),
        severity: Severity::Mortal,
        expected_len: Some((39, 39)),
        required_prefix: Some("secret_"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "LINEAR_API_KEY",
        description: "Linear API key detected",
        pattern: define_regex!(r"lin_api_[a-zA-Z0-9]{40}"),
        severity: Severity::Mortal,
        expected_len: Some((48, 48)),
        required_prefix: Some("lin_api_"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "FIGMA_TOKEN",
        description: "Figma access token detected",
        pattern: define_regex!(r"figd_[a-zA-Z0-9_-]{128,}"),
        severity: Severity::Mortal,
        expected_len: Some((133, 200)),
        required_prefix: Some("figd_"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "AIRTABLE_API_KEY",
        description: "Airtable API key detected",
        pattern: define_regex!(r"pat[a-zA-Z0-9]{14}\.[a-f0-9]{16}"),
        severity: Severity::Mortal,
        expected_len: Some((34, 34)),
        required_prefix: Some("pat"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "DIGITALOCEAN_TOKEN",
        description: "DigitalOcean API token detected",
        pattern: define_regex!(r"dop_v1_[a-f0-9]{64}"),
        severity: Severity::Mortal,
        expected_len: Some((71, 71)),
        required_prefix: Some("dop_v1_"),
        charset: Some("hex"),
    },
    Rule {
        id: "PLANETSCALE_PASSWORD",
        description: "PlanetScale database password detected",
        pattern: define_regex!(r"pscale_[a-zA-Z0-9_-]{43}"),
        severity: Severity::Mortal,
        expected_len: Some((50, 50)),
        required_prefix: Some("pscale_"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "RAILWAY_TOKEN",
        description: "Railway API token detected",
        pattern: define_regex!(r#"(?i)railway.*["'][a-zA-Z0-9_-]{32,}["']"#),
        severity: Severity::Mortal,
        expected_len: Some((32, 100)),
        required_prefix: None,
        charset: Some("alphanum"),
    },
    Rule {
        id: "RENDER_API_KEY",
        description: "Render API key detected",
        pattern: define_regex!(r"rnd_[a-zA-Z0-9_-]{48}"),
        severity: Severity::Mortal,
        expected_len: Some((52, 52)),
        required_prefix: Some("rnd_"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "NETLIFY_TOKEN",
        description: "Netlify API token detected",
        pattern: define_regex!(r"nfp_[a-zA-Z0-9_-]{40,}"),
        severity: Severity::Mortal,
        expected_len: Some((44, 60)),
        required_prefix: Some("nfp_"),
        charset: Some("alphanum"),
    },
    Rule {
        id: "JWT_TOKEN",
        description: "JWT Token detected",
        pattern: define_regex!(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*"),
        severity: Severity::Venial,
        expected_len: Some((50, 2000)),
        required_prefix: Some("eyJ"),
        charset: Some("base64"),
    },
    Rule {
        id: "HARDCODED_IP",
        description: "Hardcoded IP address detected",
        pattern: define_regex!(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        severity: Severity::Venial,
        expected_len: None,
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "EVAL_CALL",
        description: "eval() call detected (potential code injection)",
        pattern: define_regex!(r"eval\s*\("),
        severity: Severity::Venial,
        expected_len: None,
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "CREDIT_CARD",
        description: "Credit card number detected",
        pattern: define_regex!(r"\b(?:\d[ -]*?){13,16}\b"),
        severity: Severity::Mortal,
        expected_len: Some((13, 19)),
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "DOCKER_ROOT",
        description: "Dockerfile uses root user (security risk)",
        pattern: define_regex!(r"(?i)USER\s+root"),
        severity: Severity::Venial,
        expected_len: None,
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "DOCKER_LATEST",
        description: "Dockerfile uses ':latest' tag (version pinning recommended)",
        pattern: define_regex!(r"(?i)FROM\s+.*:latest"),
        severity: Severity::Venial,
        expected_len: None,
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "K8S_PRIVILEGED",
        description: "Kubernetes pod runs in privileged mode (security risk)",
        pattern: define_regex!(r"privileged:\s*true"),
        severity: Severity::Mortal,
        expected_len: None,
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "K8S_HOST_NETWORK",
        description: "Kubernetes pod uses host network (security risk)",
        pattern: define_regex!(r"hostNetwork:\s*true"),
        severity: Severity::Venial,
        expected_len: None,
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "K8S_HOST_PID",
        description: "Kubernetes pod uses host PID namespace (security risk)",
        pattern: define_regex!(r"hostPID:\s*true"),
        severity: Severity::Venial,
        expected_len: None,
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "GENERIC_API_KEY",
        description: "Generic API key pattern detected",
        pattern: define_regex!(r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]"#),
        severity: Severity::Venial,
        expected_len: Some((20, 200)),
        required_prefix: None,
        charset: Some("alphanum"),
    },
    Rule {
        id: "GENERIC_SECRET",
        description: "Generic secret pattern detected",
        pattern: define_regex!(r#"(?i)(secret|token)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]"#),
        severity: Severity::Venial,
        expected_len: Some((20, 200)),
        required_prefix: None,
        charset: Some("alphanum"),
    },
    Rule {
        id: "BRAZILIAN_CPF",
        description: "Brazilian CPF (personal ID) detected",
        pattern: define_regex!(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
        severity: Severity::Mortal,
        expected_len: Some((11, 14)),
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "BRAZILIAN_CNPJ",
        description: "Brazilian CNPJ (company ID) detected",
        pattern: define_regex!(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
        severity: Severity::Mortal,
        expected_len: Some((14, 18)),
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "NIF_PT",
        description: "Portuguese NIF (tax ID) detected",
        pattern: define_regex!(r"\b[1-9]\d{8}\b"),
        severity: Severity::Venial,
        expected_len: Some((9, 9)),
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "DNI_ES",
        description: "Spanish DNI (national ID) detected",
        pattern: define_regex!(r"\b\d{8}[A-Za-z]\b"),
        severity: Severity::Venial,
        expected_len: Some((9, 9)),
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "SSN_US",
        description: "US Social Security Number detected",
        pattern: define_regex!(r"\b\d{3}-\d{2}-\d{4}\b"),
        severity: Severity::Venial,
        expected_len: Some((11, 11)),
        required_prefix: None,
        charset: None,
    },
    Rule {
        id: "IBAN",
        description: "IBAN (International Bank Account Number) detected",
        pattern: define_regex!(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
        severity: Severity::Venial,
        expected_len: Some((15, 34)),
        required_prefix: None,
        charset: Some("alphanum"),
    },
    Rule {
        id: "DSN_CREDENTIALS",
        description: "Database connection string with credentials detected",
        pattern: define_regex!(
            r"(?i)(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|mariadb|jdbc:[a-z:]+)://[^:]+:[^@]+@"
        ),
        severity: Severity::Mortal,
        expected_len: None,
        required_prefix: None,
        charset: None,
    },
];

#[derive(Debug, Clone, Deserialize)]
struct DynamicRule {
    id: String,
    pattern: String,
    severity: String,
    description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<DynamicRule>,
}

pub struct DynamicRulesManager {
    rules_dir: PathBuf,
    compiled_rules: Arc<RwLock<Vec<CompiledCustomRule>>>,
    watcher_handle: Option<RecommendedWatcher>,
}

impl DynamicRulesManager {
    pub fn new(rules_dir: Option<PathBuf>) -> Result<Self> {
        let dir = rules_dir.unwrap_or_else(|| {
            let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            home.join(".velka").join("rules.d")
        });

        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }

        let compiled_rules = Arc::new(RwLock::new(Vec::new()));

        let mut manager = Self {
            rules_dir: dir,
            compiled_rules,
            watcher_handle: None,
        };

        manager.reload_rules()?;
        manager.setupwatcher_handle()?;

        Ok(manager)
    }

    pub fn reload_rules(&mut self) -> Result<()> {
        let mut all_rules = Vec::new();

        if !self.rules_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.rules_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let ext = path.extension().and_then(|e| e.to_str());
            match ext {
                Some("toml") => {
                    if let Ok(rules) = Self::load_toml_rules(&path) {
                        all_rules.extend(rules);
                    }
                }
                Some("yaml" | "yml") => {
                    if let Ok(rules) = Self::load_yaml_rules(&path) {
                        all_rules.extend(rules);
                    }
                }
                _ => {}
            }
        }

        let compiled = Self::compile_rules(all_rules)?;

        if let Ok(mut guard) = self.compiled_rules.write() {
            *guard = compiled;
        }

        Ok(())
    }

    fn load_toml_rules(path: &Path) -> Result<Vec<DynamicRule>> {
        let content = fs::read_to_string(path)?;
        let rules_file: RulesFile = toml::from_str(&content)
            .map_err(|e| VelkaError::Config(format!("Invalid TOML in {}: {e}", path.display())))?;
        Ok(rules_file.rules)
    }

    fn load_yaml_rules(path: &Path) -> Result<Vec<DynamicRule>> {
        let content = fs::read_to_string(path)?;
        let rules_file: RulesFile = serde_yaml::from_str(&content)
            .map_err(|e| VelkaError::Config(format!("Invalid YAML in {}: {e}", path.display())))?;
        Ok(rules_file.rules)
    }

    fn compile_rules(rules: Vec<DynamicRule>) -> Result<Vec<CompiledCustomRule>> {
        rules
            .into_iter()
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
                        .unwrap_or_else(|| format!("Dynamic rule: {}", rule.id)),
                })
            })
            .collect()
    }

    fn setupwatcher_handle(&mut self) -> Result<()> {
        let rules_dir = self.rules_dir.clone();
        let compiled_rules = Arc::clone(&self.compiled_rules);

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                if matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                ) {
                    let _ = reload_rules_internal(&rules_dir, &compiled_rules);
                }
            }
        })
        .map_err(|e| VelkaError::Config(format!("Failed to create watcher: {e}")))?;

        watcher
            .watch(&self.rules_dir, RecursiveMode::NonRecursive)
            .map_err(|e| VelkaError::Config(format!("Failed to watch directory: {e}")))?;

        self.watcher_handle = Some(watcher);
        Ok(())
    }

    #[must_use]
    pub fn get_rules(&self) -> Vec<CompiledCustomRule> {
        self.compiled_rules
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn list_rules(&self) -> Vec<(String, String, String)> {
        self.compiled_rules
            .read()
            .map(|guard| {
                guard
                    .iter()
                    .map(|r| {
                        (
                            r.id.clone(),
                            r.description.clone(),
                            format!("{:?}", r.severity),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn reload_rules_internal(
    rules_dir: &Path,
    compiled_rules: &Arc<RwLock<Vec<CompiledCustomRule>>>,
) -> Result<()> {
    let mut all_rules = Vec::new();

    for entry in fs::read_dir(rules_dir)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str());
        match ext {
            Some("toml") => {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(rules_file) = toml::from_str::<RulesFile>(&content) {
                        all_rules.extend(rules_file.rules);
                    }
                }
            }
            Some("yaml" | "yml") => {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(rules_file) = serde_yaml::from_str::<RulesFile>(&content) {
                        all_rules.extend(rules_file.rules);
                    }
                }
            }
            _ => {}
        }
    }

    let compiled: Vec<CompiledCustomRule> = all_rules
        .into_iter()
        .filter_map(|rule| {
            let pattern = Regex::new(&rule.pattern).ok()?;
            let severity = match rule.severity.to_lowercase().as_str() {
                "mortal" => Severity::Mortal,
                "venial" => Severity::Venial,
                _ => return None,
            };

            Some(CompiledCustomRule {
                id: rule.id.clone(),
                pattern,
                severity,
                description: rule
                    .description
                    .unwrap_or_else(|| format!("Dynamic rule: {}", rule.id)),
            })
        })
        .collect();

    if let Ok(mut guard) = compiled_rules.write() {
        *guard = compiled;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_builtin_rules_compile() {
        // Force lazy initialization of all rule regexes
        for rule in RULES {
            assert!(
                rule.pattern.is_match("") || !rule.pattern.is_match(""),
                "Rule {} regex failed to compile",
                rule.id
            );
        }
    }

    #[test]
    fn test_rule_ids_unique() {
        let mut seen = std::collections::HashSet::new();
        for rule in RULES {
            assert!(seen.insert(rule.id), "Duplicate rule ID: {}", rule.id);
        }
    }

    #[test]
    fn test_aws_access_key_pattern() {
        let rule = RULES.iter().find(|r| r.id == "AWS_ACCESS_KEY").unwrap();
        assert!(rule.pattern.is_match("AKIA1234567890ABCDEF"));
        assert!(!rule.pattern.is_match("AKID1234567890ABCDEF")); // Wrong prefix
        assert!(!rule.pattern.is_match("AKIA123")); // Too short
    }

    #[test]
    fn test_github_token_pattern() {
        let rule = RULES.iter().find(|r| r.id == "GITHUB_TOKEN").unwrap();
        assert!(rule
            .pattern
            .is_match("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"));
        assert!(rule
            .pattern
            .is_match("gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"));
        assert!(!rule.pattern.is_match("ghx_short")); // Invalid prefix
    }

    #[test]
    fn test_stripe_pattern() {
        let rule = RULES.iter().find(|r| r.id == "STRIPE_SECRET").unwrap();
        let fake_key = format!("sk_live_{}", "a".repeat(24));
        assert!(rule.pattern.is_match(&fake_key));
        assert!(!rule.pattern.is_match("sk_test_abc")); // sk_test not matched by this rule
    }

    #[test]
    fn test_private_key_pattern() {
        let rule = RULES.iter().find(|r| r.id == "PRIVATE_KEY").unwrap();
        assert!(rule.pattern.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(rule.pattern.is_match("-----BEGIN EC PRIVATE KEY-----"));
        assert!(!rule.pattern.is_match("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn test_dynamic_rules_manager_empty_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manager = DynamicRulesManager::new(Some(tmp.path().to_path_buf())).unwrap();
        assert!(manager.get_rules().is_empty());
    }

    #[test]
    fn test_dynamic_rules_manager_toml() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rules_content = r#"
[[rules]]
id = "CUSTOM_TEST"
pattern = "CUSTOM_[A-Z]{4}"
severity = "mortal"
description = "Custom test rule"
"#;
        fs::write(tmp.path().join("custom.toml"), rules_content).unwrap();
        let manager = DynamicRulesManager::new(Some(tmp.path().to_path_buf())).unwrap();
        let rules = manager.get_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "CUSTOM_TEST");
        assert_eq!(rules[0].severity, Severity::Mortal);
    }

    #[test]
    fn test_dynamic_rules_manager_yaml() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rules_content =
            "rules:\n  - id: YAML_RULE\n    pattern: 'YAML_[0-9]+'\n    severity: venial\n";
        fs::write(tmp.path().join("custom.yml"), rules_content).unwrap();
        let manager = DynamicRulesManager::new(Some(tmp.path().to_path_buf())).unwrap();
        let rules = manager.get_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "YAML_RULE");
        assert_eq!(rules[0].severity, Severity::Venial);
    }

    #[test]
    fn test_dynamic_rules_manager_invalid_regex() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rules_content = r#"
[[rules]]
id = "BAD_RULE"
pattern = "[invalid("
severity = "mortal"
"#;
        fs::write(tmp.path().join("bad.toml"), rules_content).unwrap();
        let manager = DynamicRulesManager::new(Some(tmp.path().to_path_buf()));
        assert!(manager.is_err());
    }

    #[test]
    fn test_dynamic_rules_list() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rules_content = r#"
[[rules]]
id = "LIST_TEST"
pattern = "TEST"
severity = "venial"
description = "List test rule"
"#;
        fs::write(tmp.path().join("list.toml"), rules_content).unwrap();
        let manager = DynamicRulesManager::new(Some(tmp.path().to_path_buf())).unwrap();
        let list = manager.list_rules();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "LIST_TEST");
    }

    #[test]
    fn test_all_mortal_rules_have_descriptions() {
        for rule in RULES {
            assert!(
                !rule.description.is_empty(),
                "Rule {} has no description",
                rule.id
            );
        }
    }
}
