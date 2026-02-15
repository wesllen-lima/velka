use rand::Rng;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Result;

const HONEYTOKEN_MARKER: &str = "velka:honeytoken";

#[derive(Debug, Clone)]
pub struct HoneyToken {
    pub token_type: String,
    pub value: String,
    pub marker: String,
}

pub fn generate_aws_key() -> HoneyToken {
    let mut rng = rand::thread_rng();
    let key: String = (0..16)
        .map(|_| {
            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            chars[rng.gen_range(0..chars.len())] as char
        })
        .collect();

    HoneyToken {
        token_type: "AWS_ACCESS_KEY".to_string(),
        value: format!("AKIA{key}"),
        marker: HONEYTOKEN_MARKER.to_string(),
    }
}

pub fn generate_github_token() -> HoneyToken {
    let mut rng = rand::thread_rng();
    let token: String = (0..36)
        .map(|_| {
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
            chars[rng.gen_range(0..chars.len())] as char
        })
        .collect();

    HoneyToken {
        token_type: "GITHUB_TOKEN".to_string(),
        value: format!("ghp_{token}"),
        marker: HONEYTOKEN_MARKER.to_string(),
    }
}

pub fn generate_stripe_key() -> HoneyToken {
    let mut rng = rand::thread_rng();
    let key: String = (0..24)
        .map(|_| {
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            chars[rng.gen_range(0..chars.len())] as char
        })
        .collect();

    HoneyToken {
        token_type: "STRIPE_SECRET".to_string(),
        value: format!("sk_live_{key}"),
        marker: HONEYTOKEN_MARKER.to_string(),
    }
}

pub fn generate_openai_key() -> HoneyToken {
    let mut rng = rand::thread_rng();
    let key: String = (0..48)
        .map(|_| {
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            chars[rng.gen_range(0..chars.len())] as char
        })
        .collect();

    HoneyToken {
        token_type: "OPENAI_API_KEY".to_string(),
        value: format!("sk-{key}"),
        marker: HONEYTOKEN_MARKER.to_string(),
    }
}

#[must_use]
pub fn generate_all() -> HashMap<String, HoneyToken> {
    let mut tokens = HashMap::new();
    tokens.insert("aws".to_string(), generate_aws_key());
    tokens.insert("github".to_string(), generate_github_token());
    tokens.insert("stripe".to_string(), generate_stripe_key());
    tokens.insert("openai".to_string(), generate_openai_key());
    tokens
}

#[allow(clippy::implicit_hasher)]
pub fn inject_to_file(file_path: &Path, tokens: &HashMap<String, HoneyToken>) -> Result<()> {
    let mut content = String::new();

    if file_path.exists() {
        content = fs::read_to_string(file_path)?;
    }

    for (key, token) in tokens {
        let line = format!(
            "{}={} # {}\n",
            key.to_uppercase(),
            token.value,
            token.marker
        );
        if !content.contains(&token.value) {
            content.push_str(&line);
        }
    }

    fs::write(file_path, content)?;
    Ok(())
}

#[allow(clippy::implicit_hasher)]
pub fn inject_to_readme(file_path: &Path, tokens: &HashMap<String, HoneyToken>) -> Result<()> {
    let mut content = String::new();

    if file_path.exists() {
        content = fs::read_to_string(file_path)?;
    }

    let mut injection = String::from("\n<!-- velka:honeytoken:start -->\n");
    injection.push_str("## Example Configuration (DO NOT USE IN PRODUCTION)\n\n");
    injection.push_str("```bash\n");

    for (key, token) in tokens {
        use std::fmt::Write;
        let _ = writeln!(injection, "export {}={}", key.to_uppercase(), token.value);
    }

    injection.push_str("```\n");
    injection.push_str("<!-- velka:honeytoken:end -->\n");

    if !content.contains("velka:honeytoken:start") {
        content.push_str(&injection);
    }

    fs::write(file_path, content)?;
    Ok(())
}

#[must_use]
pub fn is_honeytoken(line: &str) -> bool {
    line.contains(HONEYTOKEN_MARKER)
}

#[must_use]
pub fn load_honeytokens() -> HashMap<String, String> {
    let mut tokens = HashMap::new();

    let possible_paths = vec![
        PathBuf::from(".env.example"),
        PathBuf::from("README.md"),
        PathBuf::from("docs/README.md"),
    ];

    for path in possible_paths {
        if let Ok(content) = fs::read_to_string(&path) {
            for line in content.lines() {
                if is_honeytoken(line) {
                    if let Some(token) = extract_token_from_line(line) {
                        tokens.insert(token.clone(), token);
                    }
                }
            }
        }
    }

    tokens
}

fn extract_token_from_line(line: &str) -> Option<String> {
    if line.contains('=') {
        let parts: Vec<&str> = line.split('=').collect();
        if parts.len() >= 2 {
            let value = parts[1].split_whitespace().next()?;
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_aws_key() {
        let token = generate_aws_key();
        assert!(token.value.starts_with("AKIA"));
        assert_eq!(token.value.len(), 20);
    }

    #[test]
    fn test_generate_github_token() {
        let token = generate_github_token();
        assert!(token.value.starts_with("ghp_"));
        assert_eq!(token.value.len(), 40);
    }

    #[test]
    fn test_is_honeytoken() {
        assert!(is_honeytoken("AWS_KEY=AKIA1234 # velka:honeytoken"));
        assert!(!is_honeytoken("AWS_KEY=AKIA1234"));
    }

    #[test]
    fn test_generate_stripe_key() {
        let token = generate_stripe_key();
        assert!(token.value.starts_with("sk_live_"));
        assert_eq!(token.token_type, "STRIPE_SECRET");
    }

    #[test]
    fn test_generate_openai_key() {
        let token = generate_openai_key();
        assert!(token.value.starts_with("sk-"));
        assert_eq!(token.token_type, "OPENAI_API_KEY");
        assert_eq!(token.value.len(), 51); // "sk-" + 48
    }

    #[test]
    fn test_generate_all_produces_four_types() {
        let tokens = generate_all();
        assert_eq!(tokens.len(), 4);
        assert!(tokens.contains_key("aws"));
        assert!(tokens.contains_key("github"));
        assert!(tokens.contains_key("stripe"));
        assert!(tokens.contains_key("openai"));
    }

    #[test]
    fn test_inject_to_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("honeytokens.env");
        let tokens = generate_all();
        inject_to_file(&path, &tokens).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("velka:honeytoken"));
        // Injecting again should not duplicate
        inject_to_file(&path, &tokens).unwrap();
        let content2 = fs::read_to_string(&path).unwrap();
        assert_eq!(
            content.matches("velka:honeytoken").count(),
            content2.matches("velka:honeytoken").count()
        );
    }

    #[test]
    fn test_inject_to_readme() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("README.md");
        let tokens = generate_all();
        inject_to_readme(&path, &tokens).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("velka:honeytoken:start"));
        assert!(content.contains("velka:honeytoken:end"));
        // Injecting again should not duplicate
        inject_to_readme(&path, &tokens).unwrap();
        let content2 = fs::read_to_string(&path).unwrap();
        assert_eq!(
            content.matches("velka:honeytoken:start").count(),
            content2.matches("velka:honeytoken:start").count()
        );
    }

    #[test]
    fn test_extract_token_from_line() {
        let token = extract_token_from_line("AWS=AKIA1234 # velka:honeytoken");
        assert_eq!(token, Some("AKIA1234".to_string()));
    }

    #[test]
    fn test_extract_token_no_equals() {
        let token = extract_token_from_line("no equals here");
        assert!(token.is_none());
    }
}
