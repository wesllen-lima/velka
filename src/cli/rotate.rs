use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use crossbeam_channel::unbounded;

use velka::config::VelkaConfig;
use velka::domain::{Severity, Sin};
use velka::engine::investigate_with_progress;

pub fn run_rotate(
    path: &Path,
    rule_filter: Option<&str>,
    mark_remediated: bool,
    show_commands: bool,
) -> Result<()> {
    let path = path.canonicalize().with_context(|| "Invalid path")?;

    let config = VelkaConfig::load()?;
    let mut sins = {
        let (sender, receiver) = unbounded::<Sin>();
        let config = Arc::new(config);
        let sender_clone = sender.clone();
        let path_clone = path.clone();
        let config_clone = Arc::clone(&config);
        std::thread::spawn(move || {
            let _ = investigate_with_progress(&path_clone, &config_clone, &sender_clone, false);
        });
        drop(sender);
        receiver.iter().collect::<Vec<Sin>>()
    };

    sins.retain(|s| s.severity == Severity::Mortal);

    if let Some(rule_filter) = rule_filter {
        sins.retain(|s| s.rule_id == *rule_filter);
    }

    if sins.is_empty() {
        println!("No secrets found that require rotation.");
        return Ok(());
    }

    println!("Rotation Guide ({} secrets detected):\n", sins.len());

    for sin in &sins {
        let (provider, doc_url, steps) = rotation_template(&sin.rule_id);
        println!("  {} [{}:{}]", sin.rule_id, sin.path, sin.line_number);
        println!("    Provider:  {provider}");
        println!("    Docs:      {doc_url}");
        for (i, step) in steps.iter().enumerate() {
            println!("    Step {}:    {}", i + 1, step);
        }
        if show_commands {
            let cmds = rotation_cli_commands(&sin.rule_id);
            if !cmds.is_empty() {
                println!("    Executable Commands (review before running):");
                for cmd in &cmds {
                    println!("      $ {cmd}");
                }
            }
        }
        println!();
    }

    if mark_remediated {
        let history_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".velka");
        fs::create_dir_all(&history_dir)?;
        let history_file = history_dir.join("remediated.log");

        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&history_file)?;

        for sin in &sins {
            use std::io::Write;
            writeln!(
                log,
                "{}\t{}\t{}\t{}\tRemediated",
                chrono::Utc::now().to_rfc3339(),
                sin.rule_id,
                sin.path,
                sin.line_number
            )?;
        }

        println!(
            "Marked {} secret(s) as Remediated in {}",
            sins.len(),
            history_file.display()
        );
    }

    Ok(())
}

pub fn rotation_template(rule_id: &str) -> (&str, &str, Vec<&str>) {
    match rule_id {
        "AWS_ACCESS_KEY" | "AWS_SECRET_KEY" => (
            "AWS IAM",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey",
            vec![
                "Create a new access key in IAM Console",
                "Update all applications using the old key",
                "Deactivate the old key and verify",
                "Delete the old access key",
            ],
        ),
        "GITHUB_TOKEN" => (
            "GitHub",
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
            vec![
                "Go to GitHub Settings > Developer settings > Personal access tokens",
                "Regenerate or create a new token with the same scopes",
                "Update all applications using the old token",
                "Delete the old token",
            ],
        ),
        "STRIPE_SECRET" => (
            "Stripe",
            "https://docs.stripe.com/keys#rolling-keys",
            vec![
                "Go to Stripe Dashboard > Developers > API keys",
                "Roll the secret key (Stripe supports rolling keys)",
                "Update all integrations with the new key",
            ],
        ),
        "OPENAI_API_KEY" => (
            "OpenAI",
            "https://platform.openai.com/api-keys",
            vec![
                "Go to OpenAI Platform > API keys",
                "Create a new secret key",
                "Update all applications using the old key",
                "Delete the old key",
            ],
        ),
        "GOOGLE_API_KEY" | "GCP_SERVICE_ACCOUNT" => (
            "Google Cloud",
            "https://cloud.google.com/iam/docs/key-rotation",
            vec![
                "Go to Google Cloud Console > IAM > Service accounts",
                "Create a new key for the service account",
                "Update all applications",
                "Delete the old key",
            ],
        ),
        "SLACK_WEBHOOK" => (
            "Slack",
            "https://api.slack.com/messaging/webhooks",
            vec![
                "Go to Slack App settings > Incoming Webhooks",
                "Remove the compromised webhook URL",
                "Create a new webhook URL",
                "Update all integrations",
            ],
        ),
        "DB_CONNECTION_STRING" | "MONGODB_ATLAS" | "REDIS_URL" => (
            "Database",
            "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
            vec![
                "Change the database user password",
                "Update connection strings in all services",
                "Review access logs for unauthorized access",
                "Consider rotating database user entirely",
            ],
        ),
        "PRIVATE_KEY" => (
            "PKI/SSH",
            "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent",
            vec![
                "Generate a new key pair",
                "Replace public key on all authorized servers",
                "Revoke the compromised key",
                "Update CI/CD systems using the old key",
            ],
        ),
        _ => (
            "Generic",
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            vec![
                "Revoke or invalidate the compromised credential",
                "Generate a new credential with the provider",
                "Update all applications and services",
                "Audit access logs for unauthorized use",
            ],
        ),
    }
}

pub fn rotation_cli_commands(rule_id: &str) -> Vec<&'static str> {
    match rule_id {
        "AWS_ACCESS_KEY" | "AWS_SECRET_KEY" => vec![
            "aws iam create-access-key --user-name <USERNAME>",
            "aws iam update-access-key --access-key-id <OLD_KEY_ID> --status Inactive --user-name <USERNAME>",
            "aws iam delete-access-key --access-key-id <OLD_KEY_ID> --user-name <USERNAME>",
        ],
        "GITHUB_TOKEN" => vec![
            "gh auth token  # verify current token",
            "gh auth login --with-token < new_token.txt",
            "gh api -X DELETE /user/keys/<KEY_ID>  # revoke old deploy key if applicable",
        ],
        "STRIPE_SECRET" => vec![
            "# Stripe keys are rotated via Dashboard: https://dashboard.stripe.com/apikeys",
            "# After rotation, update your env:",
            "echo 'STRIPE_SECRET_KEY=sk_live_NEW_KEY' >> .env",
        ],
        "OPENAI_API_KEY" => vec![
            "# Rotate via: https://platform.openai.com/api-keys",
            "# After creating new key:",
            "echo 'OPENAI_API_KEY=sk-NEW_KEY' >> .env",
        ],
        "GOOGLE_API_KEY" | "GCP_SERVICE_ACCOUNT" => vec![
            "gcloud iam service-accounts keys create new-key.json --iam-account=<SA_EMAIL>",
            "gcloud iam service-accounts keys delete <OLD_KEY_ID> --iam-account=<SA_EMAIL>",
        ],
        "SLACK_WEBHOOK" => vec![
            "# Remove compromised webhook in Slack App settings",
            "# Create new webhook at: https://api.slack.com/apps/<APP_ID>/incoming-webhooks",
        ],
        "DB_CONNECTION_STRING" | "MONGODB_ATLAS" | "REDIS_URL" => vec![
            "# Change database password (provider-specific):",
            "# PostgreSQL: ALTER USER <user> WITH PASSWORD '<new_password>';",
            "# MongoDB Atlas: rotated via Atlas UI or CLI",
            "# Redis: CONFIG SET requirepass <new_password>",
        ],
        "PRIVATE_KEY" => vec![
            "ssh-keygen -t ed25519 -C 'rotated-key' -f ~/.ssh/id_ed25519_new",
            "ssh-copy-id -i ~/.ssh/id_ed25519_new.pub <user>@<host>",
            "# Remove old key from authorized_keys on remote hosts",
        ],
        _ => vec![],
    }
}
