//! Runtime log scanner for monitoring container stdout/stderr in real-time.
//!
//! Scans streaming log sources (stdin, files, network) line-by-line using the
//! same rule engine as the file scanner. Emits [`RuntimeAlert`]s when secret
//! patterns are detected.
//!
//! # Modes
//!
//! - **Stream**: Scan a finite reader (stdin, file) to completion.
//! - **Tail** (`--follow`): Seek to end of file and continuously watch for new lines.
//!
//! # Usage
//!
//! ```bash
//! kubectl logs -f my-pod | velka runtime
//! velka runtime /var/log/app.log --follow
//! ```

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use crate::config::VelkaConfig;
use crate::domain::{Severity, Sin};
use crate::engine::rules::RULES;

/// Alert emitted when a secret pattern is found in a log stream.
#[derive(Debug, Clone)]
pub struct RuntimeAlert {
    pub sin: Sin,
    pub source: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Scan a streaming async reader (e.g. container stdout) line-by-line.
/// Sends alerts through the channel whenever a secret pattern matches.
pub async fn scan_stream<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    reader: R,
    source: String,
    _config: Arc<VelkaConfig>,
    tx: mpsc::UnboundedSender<RuntimeAlert>,
) -> anyhow::Result<()> {
    let buf = BufReader::new(reader);
    let mut lines = buf.lines();
    let mut line_number: usize = 0;

    while let Some(line) = lines.next_line().await? {
        line_number += 1;

        for rule in RULES {
            if rule.pattern.is_match(&line) {
                let sin = Sin {
                    path: source.clone(),
                    line_number,
                    snippet: redact_line(&line),
                    context: vec![],
                    severity: rule.severity,
                    description: rule.description.to_string(),
                    rule_id: rule.id.to_string(),
                    commit_hash: None,
                    verified: None,
                    confidence: None,
                    confidence_factors: None,
                };

                let alert = RuntimeAlert {
                    sin,
                    source: source.clone(),
                    timestamp: chrono::Utc::now(),
                };

                if tx.send(alert).is_err() {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

/// Monitor a log file path using tokio, tailing new lines as they appear.
pub async fn tail_and_scan(
    path: &std::path::Path,
    source: String,
    _config: Arc<VelkaConfig>,
    tx: mpsc::UnboundedSender<RuntimeAlert>,
) -> anyhow::Result<()> {
    use tokio::fs::File;
    use tokio::time::{sleep, Duration};

    let mut line_number: usize = 0;

    // Seek to end to only scan new output
    let metadata = tokio::fs::metadata(path).await?;
    let file_size = metadata.len();
    let file = File::open(path).await?;
    let mut buf = BufReader::new(file);

    // Skip to end
    let mut skip_buf = String::new();
    let mut skipped: u64 = 0;
    while skipped < file_size {
        skip_buf.clear();
        match buf.read_line(&mut skip_buf).await? {
            0 => break,
            n => {
                skipped += n as u64;
                line_number += 1;
            }
        }
    }

    // Now tail new lines
    loop {
        let mut line = String::new();
        if buf.read_line(&mut line).await? == 0 {
            sleep(Duration::from_millis(100)).await;
            continue;
        }
        line_number += 1;
        let trimmed = line.trim_end();

        for rule in RULES {
            if rule.pattern.is_match(trimmed) {
                let sin = Sin {
                    path: path.to_string_lossy().to_string(),
                    line_number,
                    snippet: redact_line(trimmed),
                    context: vec![],
                    severity: rule.severity,
                    description: rule.description.to_string(),
                    rule_id: rule.id.to_string(),
                    commit_hash: None,
                    verified: None,
                    confidence: None,
                    confidence_factors: None,
                };

                let alert = RuntimeAlert {
                    sin,
                    source: source.clone(),
                    timestamp: chrono::Utc::now(),
                };

                if tx.send(alert).is_err() {
                    return Ok(());
                }
            }
        }
    }
}

/// Run the runtime scanner CLI: reads from stdin or a given log source.
pub async fn run_runtime_monitor(sources: Vec<String>, follow: bool) -> anyhow::Result<()> {
    let config = Arc::new(VelkaConfig::load()?);
    let (tx, mut rx) = mpsc::unbounded_channel::<RuntimeAlert>();

    if sources.is_empty() {
        // Read from stdin
        let stdin = tokio::io::stdin();
        let source = "stdin".to_string();
        let config_clone = config.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = scan_stream(stdin, source, config_clone, tx_clone).await {
                eprintln!("[velka-runtime] stdin error: {e}");
            }
        });
    } else {
        for src in &sources {
            let path = std::path::PathBuf::from(src);
            if path.exists() {
                let source = src.clone();
                let config_clone = config.clone();
                let tx_clone = tx.clone();
                let path_clone = path.clone();
                if follow {
                    tokio::spawn(async move {
                        if let Err(e) =
                            tail_and_scan(&path_clone, source, config_clone, tx_clone).await
                        {
                            eprintln!(
                                "[velka-runtime] tail error for {}: {e}",
                                path_clone.display()
                            );
                        }
                    });
                } else {
                    tokio::spawn(async move {
                        let file = match tokio::fs::File::open(&path_clone).await {
                            Ok(f) => f,
                            Err(e) => {
                                eprintln!(
                                    "[velka-runtime] open error for {}: {e}",
                                    path_clone.display()
                                );
                                return;
                            }
                        };
                        if let Err(e) = scan_stream(file, source, config_clone, tx_clone).await {
                            eprintln!(
                                "[velka-runtime] scan error for {}: {e}",
                                path_clone.display()
                            );
                        }
                    });
                }
            } else {
                eprintln!("[velka-runtime] source not found: {src}");
            }
        }
    }

    // Drop our sender so rx closes when all spawned tasks finish
    drop(tx);

    let mut mortal_count = 0usize;
    while let Some(alert) = rx.recv().await {
        let severity_str = match alert.sin.severity {
            Severity::Mortal => "\x1b[31mMORTAL\x1b[0m",
            Severity::Venial => "\x1b[33mVENIAL\x1b[0m",
        };

        eprintln!(
            "[{timestamp}] [{severity}] {rule} in {source}:{line} — {desc}",
            timestamp = alert.timestamp.format("%H:%M:%S"),
            severity = severity_str,
            rule = alert.sin.rule_id,
            source = alert.source,
            line = alert.sin.line_number,
            desc = alert.sin.description,
        );

        if alert.sin.severity == Severity::Mortal {
            mortal_count += 1;
        }
    }

    if mortal_count > 0 {
        eprintln!("\n[velka-runtime] {mortal_count} mortal secret(s) detected in runtime logs.");
        std::process::exit(1);
    }

    Ok(())
}

/// Redact the middle portion of a matched line to avoid leaking secrets in alerts.
fn redact_line(line: &str) -> String {
    if line.len() <= 20 {
        return line.to_string();
    }
    let visible = 8;
    format!(
        "{}...REDACTED...{}",
        &line[..visible],
        &line[line.len().saturating_sub(visible)..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_stream_detects_secret() {
        let log_data = b"INFO: starting app\nUsing key AKIA0000000000000000 for auth\nINFO: done\n";
        let _cursor = std::io::Cursor::new(log_data.to_vec());
        let reader =
            tokio_util::io::StreamReader::new(tokio_stream::iter(vec![Ok::<_, std::io::Error>(
                bytes::Bytes::from(log_data.to_vec()),
            )]));

        let config = Arc::new(VelkaConfig::default());
        let (tx, mut rx) = mpsc::unbounded_channel();

        let source = "test-container".to_string();
        scan_stream(reader, source, config, tx).await.unwrap();

        let alert = rx.recv().await;
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().sin.rule_id, "AWS_ACCESS_KEY");
    }
}
