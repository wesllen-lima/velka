use once_cell::sync::Lazy;
use regex::Regex;

use crate::domain::Rule;
use crate::domain::Severity;

macro_rules! define_regex {
    ($re:literal) => {{
        static PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new($re).expect("Invalid regex pattern"));
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
        pattern: define_regex!(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
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
        description: "eval() call detected",
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
];
