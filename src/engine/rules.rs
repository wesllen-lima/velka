use regex::Regex;
use std::sync::LazyLock;

use crate::domain::Rule;
use crate::domain::Severity;

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
    },
    Rule {
        id: "AWS_SECRET_KEY",
        description: "AWS Secret Access Key detected",
        pattern: define_regex!(r#"(?i)aws_secret_access_key.*['"][A-Za-z0-9/+=]{40}['"]"#),
        severity: Severity::Mortal,
    },
    Rule {
        id: "GOOGLE_API_KEY",
        description: "Google API Key detected",
        pattern: define_regex!(r"AIza[0-9A-Za-z\-_]{35}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "GITHUB_TOKEN",
        description: "GitHub Personal Access Token detected",
        pattern: define_regex!(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "STRIPE_SECRET",
        description: "Stripe Secret Key detected",
        pattern: define_regex!(r"sk_live_[0-9a-zA-Z]{24,}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "PRIVATE_KEY",
        description: "Private Key detected",
        pattern: define_regex!(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) PRIVATE KEY-----"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "SLACK_WEBHOOK",
        description: "Slack Webhook URL detected",
        pattern: define_regex!(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
        ),
        severity: Severity::Mortal,
    },
    Rule {
        id: "SENDGRID_API",
        description: "SendGrid API Key detected",
        pattern: define_regex!(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "TWILIO_API",
        description: "Twilio API Key detected",
        pattern: define_regex!(r"SK[a-f0-9]{32}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "NPM_TOKEN",
        description: "NPM Auth Token detected",
        pattern: define_regex!(r"npm_[A-Za-z0-9]{36}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "PYPI_TOKEN",
        description: "PyPI API Token detected",
        pattern: define_regex!(r"pypi-[A-Za-z0-9_-]{60,}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "DISCORD_TOKEN",
        description: "Discord Bot Token detected",
        pattern: define_regex!(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "TELEGRAM_BOT",
        description: "Telegram Bot Token detected",
        pattern: define_regex!(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "DB_CONNECTION_STRING",
        description: "Database connection string detected",
        pattern: define_regex!(r"(?i)(postgres|mysql|mongodb|redis|mssql)://[^\s]+"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "HARDCODED_PASSWORD",
        description: "Hardcoded password detected",
        pattern: define_regex!(r#"(?i)(password|passwd|pwd|secret)\s*[:=]\s*['"][^'"]{8,}['"]"#),
        severity: Severity::Mortal,
    },
    Rule {
        id: "AZURE_STORAGE_KEY",
        description: "Azure Storage Account Key detected",
        pattern: define_regex!(
            r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"
        ),
        severity: Severity::Mortal,
    },
    Rule {
        id: "GCP_SERVICE_ACCOUNT",
        description: "GCP Service Account Key detected",
        pattern: define_regex!(r#""type"\s*:\s*"service_account""#),
        severity: Severity::Mortal,
    },
    Rule {
        id: "HEROKU_API_KEY",
        description: "Heroku API Key detected",
        pattern: define_regex!(
            r"[hH]eroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ),
        severity: Severity::Mortal,
    },
    Rule {
        id: "MAILGUN_API_KEY",
        description: "Mailgun API Key detected",
        pattern: define_regex!(r"key-[0-9a-zA-Z]{32}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "SQUARE_ACCESS_TOKEN",
        description: "Square Access Token detected",
        pattern: define_regex!(r"sq0atp-[0-9A-Za-z\-_]{22}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "SQUARE_OAUTH_SECRET",
        description: "Square OAuth Secret detected",
        pattern: define_regex!(r"sq0csp-[0-9A-Za-z\-_]{43}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "DATADOG_API_KEY",
        description: "Datadog API Key detected",
        pattern: define_regex!(r#"(?i)datadog.*["'][a-f0-9]{32}["']"#),
        severity: Severity::Mortal,
    },
    Rule {
        id: "NEW_RELIC_LICENSE",
        description: "New Relic license key detected",
        pattern: define_regex!(r#"(?i)newrelic.*["'][a-f0-9]{40}["']"#),
        severity: Severity::Mortal,
    },
    Rule {
        id: "CLOUDFLARE_API_KEY",
        description: "Cloudflare API key/token detected",
        pattern: define_regex!(r#"(?i)cloudflare.*["'][a-zA-Z0-9_-]{37}["']"#),
        severity: Severity::Mortal,
    },
    Rule {
        id: "OPENAI_API_KEY",
        description: "OpenAI API key detected",
        pattern: define_regex!(r"sk-[a-zA-Z0-9]{48}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "SUPABASE_ANON_KEY",
        description: "Supabase anon/service key detected",
        pattern: define_regex!(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "VERCEL_TOKEN",
        description: "Vercel API token detected",
        pattern: define_regex!(r#"(?i)vercel.*["'][a-zA-Z0-9_]{24}["']"#),
        severity: Severity::Mortal,
    },
    Rule {
        id: "MONGODB_ATLAS",
        description: "MongoDB Atlas connection string detected",
        pattern: define_regex!(r"mongodb(\+srv)?://[^\s]+"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "REDIS_URL",
        description: "Redis connection URL detected",
        pattern: define_regex!(r"rediss?://[^\s]+"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "SENTRY_DSN",
        description: "Sentry DSN detected",
        pattern: define_regex!(r"https://[a-f0-9]+@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "ALGOLIA_API_KEY",
        description: "Algolia API key detected",
        pattern: define_regex!(r#"(?i)algolia.*["'][a-zA-Z0-9]{32}["']"#),
        severity: Severity::Mortal,
    },
    Rule {
        id: "NOTION_API_KEY",
        description: "Notion API secret detected",
        pattern: define_regex!(r"secret_[a-zA-Z0-9]{32}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "LINEAR_API_KEY",
        description: "Linear API key detected",
        pattern: define_regex!(r"lin_api_[a-zA-Z0-9]{40}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "FIGMA_TOKEN",
        description: "Figma access token detected",
        pattern: define_regex!(r"figd_[a-zA-Z0-9_-]{128,}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "AIRTABLE_API_KEY",
        description: "Airtable API key detected",
        pattern: define_regex!(r"pat[a-zA-Z0-9]{14}\.[a-f0-9]{16}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "DIGITALOCEAN_TOKEN",
        description: "DigitalOcean API token detected",
        pattern: define_regex!(r"dop_v1_[a-f0-9]{64}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "PLANETSCALE_PASSWORD",
        description: "PlanetScale database password detected",
        pattern: define_regex!(r"pscale_[a-zA-Z0-9_-]{43}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "RAILWAY_TOKEN",
        description: "Railway API token detected",
        pattern: define_regex!(r#"(?i)railway.*["'][a-zA-Z0-9_-]{32,}["']"#),
        severity: Severity::Mortal,
    },
    Rule {
        id: "RENDER_API_KEY",
        description: "Render API key detected",
        pattern: define_regex!(r"rnd_[a-zA-Z0-9_-]{48}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "NETLIFY_TOKEN",
        description: "Netlify API token detected",
        pattern: define_regex!(r"nfp_[a-zA-Z0-9_-]{40,}"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "JWT_TOKEN",
        description: "JWT Token detected",
        pattern: define_regex!(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*"),
        severity: Severity::Venial,
    },
    Rule {
        id: "HARDCODED_IP",
        description: "Hardcoded IP address detected",
        pattern: define_regex!(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        severity: Severity::Venial,
    },
    Rule {
        id: "EVAL_CALL",
        description: "eval() call detected (potential code injection)",
        pattern: define_regex!(r"eval\s*\("),
        severity: Severity::Venial,
    },
    Rule {
        id: "CREDIT_CARD",
        description: "Credit card number detected",
        pattern: define_regex!(r"\b(?:\d[ -]*?){13,16}\b"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "DOCKER_ROOT",
        description: "Dockerfile uses root user (security risk)",
        pattern: define_regex!(r"(?i)USER\s+root"),
        severity: Severity::Venial,
    },
    Rule {
        id: "DOCKER_LATEST",
        description: "Dockerfile uses ':latest' tag (version pinning recommended)",
        pattern: define_regex!(r"(?i)FROM\s+.*:latest"),
        severity: Severity::Venial,
    },
    Rule {
        id: "K8S_PRIVILEGED",
        description: "Kubernetes pod runs in privileged mode (security risk)",
        pattern: define_regex!(r"privileged:\s*true"),
        severity: Severity::Mortal,
    },
    Rule {
        id: "K8S_HOST_NETWORK",
        description: "Kubernetes pod uses host network (security risk)",
        pattern: define_regex!(r"hostNetwork:\s*true"),
        severity: Severity::Venial,
    },
    Rule {
        id: "K8S_HOST_PID",
        description: "Kubernetes pod uses host PID namespace (security risk)",
        pattern: define_regex!(r"hostPID:\s*true"),
        severity: Severity::Venial,
    },
    Rule {
        id: "GENERIC_API_KEY",
        description: "Generic API key pattern detected",
        pattern: define_regex!(r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]"#),
        severity: Severity::Venial,
    },
    Rule {
        id: "GENERIC_SECRET",
        description: "Generic secret pattern detected",
        pattern: define_regex!(r#"(?i)(secret|token)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]"#),
        severity: Severity::Venial,
    },
];
