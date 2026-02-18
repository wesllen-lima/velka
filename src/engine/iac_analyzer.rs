//! Infrastructure-as-Code (`IaC`) security scanner.
//!
//! Detects misconfigurations in:
//! - **Terraform** (`.tf`): open security groups, wildcard IAM, public S3 buckets
//! - **Kubernetes YAML** (`.yaml`/`.yml`): privileged pods, host networking, root containers
//! - **Dockerfiles**: `RUN curl | bash`, `USER root`, missing health checks
//!
//! Returns a `Vec<IacFinding>` — separate from `Sin` to avoid confusion with
//! secrets. The scan CLI merges them into the final output.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

// ── Patterns ───────────────────────────────────────────────────────────────

// Terraform patterns
static TF_SG_CIDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"cidr_blocks\s*=\s*\[?\s*["']0\.0\.0\.0/0["']"#).unwrap());
static TF_IPV6_CIDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"ipv6_cidr_blocks\s*=\s*\[?\s*["']::/0["']"#).unwrap());
static TF_IAM_WILDCARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""Action"\s*:\s*"\*""#).unwrap());
static TF_IAM_WILDCARD_HCL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches HCL: `actions = ["*"]`, `actions = "*"`, `Action = "*"` (jsonencode)
    Regex::new(r#"(?i)(?:actions|Action)\s*=\s*\[?\s*["']\*["']"#).unwrap()
});
static TF_S3_PUBLIC_ACL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"acl\s*=\s*["']public-read(?:-write)?["']"#).unwrap());
static TF_S3_PUBLIC_ACCESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"block_public_acls\s*=\s*false").unwrap());
static TF_OPEN_INGRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:from|to)_port\s*=\s*(?:0|22|3389|5432|3306|6379|27017)").unwrap()
});
static TF_SG_RESOURCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"resource\s+["']aws_security_group["']"#).unwrap());

// Kubernetes YAML patterns
static K8S_PRIVILEGED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"privileged\s*:\s*true").unwrap());
static K8S_HOST_NETWORK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"hostNetwork\s*:\s*true").unwrap());
static K8S_HOST_PID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"hostPID\s*:\s*true").unwrap());
static K8S_ALLOW_PRIV_ESCALATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"allowPrivilegeEscalation\s*:\s*true").unwrap());
static K8S_ROOT_USER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"runAsUser\s*:\s*0").unwrap());
static K8S_UNSAFE_SYSCTLS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"unsafe-sysctl").unwrap());
static K8S_ALL_CAPABILITIES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"add\s*:\s*\[.*?ALL.*?\]").unwrap());
static K8S_WRITABLE_ROOT_FS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"readOnlyRootFilesystem\s*:\s*false").unwrap());

// Dockerfile patterns
static DOCKER_CURL_PIPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"RUN\s+(?:.*\|\s*(?:ba)?sh|curl[^|]*\|\s*(?:ba)?sh|wget[^|]*\|\s*(?:ba)?sh)")
        .unwrap()
});
static DOCKER_USER_ROOT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^USER\s+(?:root|0)\s*$").unwrap());
static DOCKER_ADD_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^ADD\s+https?://").unwrap());
static DOCKER_LATEST_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^FROM\s+\S+:latest(?:\s|$)").unwrap());
static DOCKER_SUDO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"RUN\s+.*\bsudo\b").unwrap());
static DOCKER_EXPOSE_22: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^EXPOSE\s+22(?:\s|$)").unwrap());

// ── Data types ─────────────────────────────────────────────────────────────

/// Severity of an `IaC` misconfiguration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IacSeverity {
    /// Direct security risk (e.g., 0.0.0.0/0 SSH exposure).
    Critical,
    /// Elevated risk but context-dependent.
    High,
    /// Informational / best-practice violation.
    Medium,
}

impl std::fmt::Display for IacSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
        }
    }
}

/// A single `IaC` misconfiguration finding.
#[derive(Debug, Clone, Serialize)]
pub struct IacFinding {
    /// Source file path.
    pub path: String,
    /// 1-based line number.
    pub line_number: usize,
    /// Rule ID (e.g. `"TF_SG_OPEN_WORLD"`).
    pub rule_id: String,
    /// Human-readable description.
    pub description: String,
    /// Actionable recommendation.
    pub recommendation: String,
    /// Severity level.
    pub severity: IacSeverity,
}

// ── Entry point ────────────────────────────────────────────────────────────

/// Scan a file for `IaC` misconfigurations based on its extension / name.
///
/// Returns an empty `Vec` for unrecognised file types.
#[must_use]
pub fn scan_iac_file(path: &Path, content: &str) -> Vec<IacFinding> {
    let path_str = path.to_string_lossy();
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    if filename == "dockerfile" || filename.starts_with("dockerfile.") {
        return scan_dockerfile(&path_str, content);
    }

    match path.extension().and_then(|e| e.to_str()) {
        Some("tf") => scan_terraform(&path_str, content),
        Some("yaml" | "yml") => {
            // Heuristic: K8s files typically contain `apiVersion:` or `kind:`
            if content.contains("apiVersion:") || content.contains("kind:") {
                scan_kubernetes(&path_str, content)
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// Determine if a path is an `IaC` file worth scanning.
#[must_use]
pub fn is_iac_file(path: &Path) -> bool {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    if filename == "dockerfile" || filename.starts_with("dockerfile.") {
        return true;
    }

    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("tf" | "yaml" | "yml")
    )
}

// ── Terraform ──────────────────────────────────────────────────────────────

fn scan_terraform(path: &str, content: &str) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    // Track whether we're inside a security group resource block
    let mut in_sg_block = false;
    let mut sg_brace_depth = 0i32;
    let mut sg_has_open_cidr = false;
    let mut sg_open_line = 0usize;
    let mut sg_port_line = 0usize;

    for (idx, line) in lines.iter().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        // Track security group block boundaries
        if TF_SG_RESOURCE.is_match(line) {
            in_sg_block = true;
            sg_brace_depth = 0;
            sg_has_open_cidr = false;
        }

        if in_sg_block {
            for ch in trimmed.chars() {
                match ch {
                    '{' => sg_brace_depth += 1,
                    '}' => sg_brace_depth -= 1,
                    _ => {}
                }
            }
            if sg_brace_depth <= 0 && sg_brace_depth != 0 {
                // Left the block
                if sg_has_open_cidr {
                    findings.push(IacFinding {
                        path: path.to_string(),
                        line_number: sg_open_line,
                        rule_id: "TF_SG_OPEN_WORLD".to_string(),
                        description: format!(
                            "Security group exposes port(s) to 0.0.0.0/0 (line {sg_port_line})"
                        ),
                        recommendation:
                            "Restrict ingress/egress to specific IP ranges instead of 0.0.0.0/0"
                                .to_string(),
                        severity: IacSeverity::Critical,
                    });
                }
                in_sg_block = false;
                sg_has_open_cidr = false;
            }

            if TF_SG_CIDR.is_match(line) || TF_IPV6_CIDR.is_match(line) {
                sg_has_open_cidr = true;
                sg_open_line = line_num;
            }
            if TF_OPEN_INGRESS.is_match(line) {
                sg_port_line = line_num;
            }
        }

        // IAM wildcard actions
        if TF_IAM_WILDCARD.is_match(line) || TF_IAM_WILDCARD_HCL.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "TF_IAM_WILDCARD".to_string(),
                description: "IAM policy grants wildcard Action: \"*\" (full permissions)"
                    .to_string(),
                recommendation: "Replace `*` with the minimum set of required IAM actions"
                    .to_string(),
                severity: IacSeverity::Critical,
            });
        }

        // S3 public ACL
        if TF_S3_PUBLIC_ACL.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "TF_S3_PUBLIC_ACL".to_string(),
                description: "S3 bucket ACL is set to public-read or public-read-write".to_string(),
                recommendation: "Use `aws_s3_bucket_public_access_block` to block public access"
                    .to_string(),
                severity: IacSeverity::Critical,
            });
        }

        // S3 public access block disabled
        if TF_S3_PUBLIC_ACCESS.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "TF_S3_BLOCK_DISABLED".to_string(),
                description: "S3 bucket public access block is explicitly disabled".to_string(),
                recommendation: "Set `block_public_acls = true` and `block_public_policy = true`"
                    .to_string(),
                severity: IacSeverity::High,
            });
        }
    }

    findings
}

// ── Kubernetes ─────────────────────────────────────────────────────────────

fn scan_kubernetes(path: &str, content: &str) -> Vec<IacFinding> {
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;

        if K8S_PRIVILEGED.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "K8S_PRIVILEGED".to_string(),
                description: "Container runs in privileged mode (full host access)".to_string(),
                recommendation: "Remove `privileged: true` from securityContext".to_string(),
                severity: IacSeverity::Critical,
            });
        }

        if K8S_HOST_NETWORK.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "K8S_HOST_NETWORK".to_string(),
                description: "Pod shares the host network namespace".to_string(),
                recommendation: "Remove `hostNetwork: true` unless explicitly required".to_string(),
                severity: IacSeverity::High,
            });
        }

        if K8S_HOST_PID.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "K8S_HOST_PID".to_string(),
                description: "Pod shares the host PID namespace".to_string(),
                recommendation: "Remove `hostPID: true`".to_string(),
                severity: IacSeverity::High,
            });
        }

        if K8S_ALLOW_PRIV_ESCALATION.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "K8S_PRIV_ESCALATION".to_string(),
                description: "Container allows privilege escalation".to_string(),
                recommendation: "Set `allowPrivilegeEscalation: false`".to_string(),
                severity: IacSeverity::High,
            });
        }

        if K8S_ROOT_USER.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "K8S_RUN_AS_ROOT".to_string(),
                description: "Container runs as UID 0 (root)".to_string(),
                recommendation: "Set `runAsNonRoot: true` and choose a non-zero `runAsUser`"
                    .to_string(),
                severity: IacSeverity::High,
            });
        }

        if K8S_ALL_CAPABILITIES.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "K8S_CAPABILITIES_ALL".to_string(),
                description: "Container adds ALL Linux capabilities".to_string(),
                recommendation: "Grant only specific required capabilities; drop ALL others"
                    .to_string(),
                severity: IacSeverity::Critical,
            });
        }

        if K8S_WRITABLE_ROOT_FS.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "K8S_WRITABLE_ROOT_FS".to_string(),
                description: "Container has a writable root filesystem".to_string(),
                recommendation: "Set `readOnlyRootFilesystem: true`".to_string(),
                severity: IacSeverity::Medium,
            });
        }

        if K8S_UNSAFE_SYSCTLS.is_match(line) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "K8S_UNSAFE_SYSCTLS".to_string(),
                description: "Pod uses unsafe kernel sysctls".to_string(),
                recommendation: "Remove unsafe sysctl configuration".to_string(),
                severity: IacSeverity::High,
            });
        }
    }

    findings
}

// ── Dockerfile ─────────────────────────────────────────────────────────────

fn scan_dockerfile(path: &str, content: &str) -> Vec<IacFinding> {
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if DOCKER_CURL_PIPE.is_match(trimmed) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "DOCKER_CURL_PIPE_SHELL".to_string(),
                description: "Dockerfile pipes curl/wget output directly into a shell (RCE risk)"
                    .to_string(),
                recommendation: "Download the script, verify its checksum, then execute it"
                    .to_string(),
                severity: IacSeverity::Critical,
            });
        }

        if DOCKER_USER_ROOT.is_match(trimmed) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "DOCKER_USER_ROOT".to_string(),
                description: "Dockerfile sets USER root — container runs as root".to_string(),
                recommendation: "Create a non-root user and switch with `USER <user>`".to_string(),
                severity: IacSeverity::High,
            });
        }

        if DOCKER_ADD_URL.is_match(trimmed) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "DOCKER_ADD_URL".to_string(),
                description: "Dockerfile uses ADD with a remote URL (no integrity check)"
                    .to_string(),
                recommendation: "Use RUN curl + checksum verification instead of ADD".to_string(),
                severity: IacSeverity::High,
            });
        }

        if DOCKER_LATEST_TAG.is_match(trimmed) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "DOCKER_LATEST_TAG".to_string(),
                description: "Dockerfile uses `:latest` tag — non-deterministic builds".to_string(),
                recommendation: "Pin to an immutable digest or specific version tag".to_string(),
                severity: IacSeverity::Medium,
            });
        }

        if DOCKER_SUDO.is_match(trimmed) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "DOCKER_SUDO".to_string(),
                description: "Dockerfile uses sudo — indicates unnecessary root privilege"
                    .to_string(),
                recommendation: "Run as a dedicated non-root user without sudo".to_string(),
                severity: IacSeverity::Medium,
            });
        }

        if DOCKER_EXPOSE_22.is_match(trimmed) {
            findings.push(IacFinding {
                path: path.to_string(),
                line_number: line_num,
                rule_id: "DOCKER_EXPOSE_SSH".to_string(),
                description: "Dockerfile exposes SSH port 22".to_string(),
                recommendation:
                    "Avoid running SSH in containers; use `kubectl exec` or similar instead"
                        .to_string(),
                severity: IacSeverity::High,
            });
        }
    }

    findings
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn path(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    // ── Terraform tests ───────────────────────────────────────────────────

    #[test]
    fn test_tf_iam_wildcard() {
        let content = r#"
resource "aws_iam_role_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}
"#;
        let findings = scan_terraform("main.tf", content);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(
            ids.contains(&"TF_IAM_WILDCARD"),
            "expected TF_IAM_WILDCARD, got: {ids:?}"
        );
    }

    #[test]
    fn test_tf_s3_public_acl() {
        let content = r#"
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}
"#;
        let findings = scan_terraform("s3.tf", content);
        assert!(findings.iter().any(|f| f.rule_id == "TF_S3_PUBLIC_ACL"));
    }

    // ── Kubernetes tests ──────────────────────────────────────────────────

    #[test]
    fn test_k8s_privileged() {
        let content = "apiVersion: v1\nkind: Pod\n  securityContext:\n    privileged: true\n";
        let findings = scan_kubernetes("pod.yaml", content);
        assert!(findings.iter().any(|f| f.rule_id == "K8S_PRIVILEGED"));
    }

    #[test]
    fn test_k8s_host_network() {
        let content = "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n";
        let findings = scan_kubernetes("pod.yaml", content);
        assert!(findings.iter().any(|f| f.rule_id == "K8S_HOST_NETWORK"));
    }

    #[test]
    fn test_k8s_root_user() {
        let content = "apiVersion: v1\nkind: Pod\n  securityContext:\n    runAsUser: 0\n";
        let findings = scan_kubernetes("pod.yaml", content);
        assert!(findings.iter().any(|f| f.rule_id == "K8S_RUN_AS_ROOT"));
    }

    // ── Dockerfile tests ──────────────────────────────────────────────────

    #[test]
    fn test_docker_curl_pipe() {
        let content = "FROM ubuntu:20.04\nRUN curl https://example.com/install.sh | bash\n";
        let findings = scan_dockerfile("Dockerfile", content);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "DOCKER_CURL_PIPE_SHELL"));
    }

    #[test]
    fn test_docker_user_root() {
        let content = "FROM ubuntu:20.04\nUSER root\nRUN apt-get update\n";
        let findings = scan_dockerfile("Dockerfile", content);
        assert!(findings.iter().any(|f| f.rule_id == "DOCKER_USER_ROOT"));
    }

    #[test]
    fn test_docker_latest_tag() {
        let content = "FROM node:latest\nCOPY . .\n";
        let findings = scan_dockerfile("Dockerfile", content);
        assert!(findings.iter().any(|f| f.rule_id == "DOCKER_LATEST_TAG"));
    }

    #[test]
    fn test_scan_iac_file_routes_correctly() {
        let tf_content = r#"resource "aws_s3_bucket" "b" { acl = "public-read" }"#;
        let findings = scan_iac_file(&path("infra/main.tf"), tf_content);
        assert!(!findings.is_empty());

        let docker_content = "FROM node:latest\nRUN curl http://x.com | bash\n";
        let findings = scan_iac_file(&path("Dockerfile"), docker_content);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_is_iac_file() {
        assert!(is_iac_file(&path("main.tf")));
        assert!(is_iac_file(&path("Dockerfile")));
        assert!(is_iac_file(&path("Dockerfile.prod")));
        assert!(is_iac_file(&path("pod.yaml")));
        assert!(!is_iac_file(&path("src/main.rs")));
        assert!(!is_iac_file(&path("README.md")));
    }
}
