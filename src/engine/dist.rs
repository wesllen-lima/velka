//! Distributed scan orchestration for scanning multiple repositories in parallel.
//!
//! Provides a client-server model where an [`ScanOrchestrator`] distributes
//! [`ScanJob`] units across remote worker nodes. Each worker clones the target
//! repo to a temporary directory, runs a Velka scan, and returns the results.
//!
//! # Architecture
//!
//! ```text
//! Orchestrator ──> Worker 1 (HTTP POST /scan)
//!             ──> Worker 2
//!             ──> Worker N
//! ```
//!
//! Jobs are distributed round-robin. Results are aggregated asynchronously.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::VelkaConfig;
use crate::domain::Sin;

/// A unit of work for distributed scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: String,
    pub repo_url: String,
    pub branch: Option<String>,
    pub deep_scan: bool,
}

/// Result from a completed scan job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJobResult {
    pub job_id: String,
    pub repo_url: String,
    pub sins: Vec<SerializableSin>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Serializable version of Sin for network transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSin {
    pub path: String,
    pub line_number: usize,
    pub snippet: String,
    pub severity: String,
    pub description: String,
    pub rule_id: String,
}

impl From<&Sin> for SerializableSin {
    fn from(sin: &Sin) -> Self {
        Self {
            path: sin.path.clone(),
            line_number: sin.line_number,
            snippet: sin.snippet.clone(),
            severity: format!("{:?}", sin.severity),
            description: sin.description.clone(),
            rule_id: sin.rule_id.clone(),
        }
    }
}

/// Orchestrator that distributes scan jobs across worker nodes.
pub struct ScanOrchestrator {
    workers: Vec<String>,
    _config: Arc<VelkaConfig>,
}

impl ScanOrchestrator {
    #[must_use]
    pub fn new(workers: Vec<String>, config: VelkaConfig) -> Self {
        Self {
            workers,
            _config: Arc::new(config),
        }
    }

    /// Distribute jobs round-robin across registered workers.
    /// Returns aggregated results from all workers.
    pub async fn distribute(&self, jobs: Vec<ScanJob>) -> Vec<ScanJobResult> {
        let (tx, mut rx) = mpsc::unbounded_channel::<ScanJobResult>();
        let client = reqwest::Client::new();

        for (i, job) in jobs.into_iter().enumerate() {
            let worker = &self.workers[i % self.workers.len()];
            let url = format!("{worker}/scan");
            let tx_clone = tx.clone();
            let client_clone = client.clone();

            tokio::spawn(async move {
                let result = match client_clone.post(&url).json(&job).send().await {
                    Ok(resp) => match resp.json::<ScanJobResult>().await {
                        Ok(r) => r,
                        Err(e) => ScanJobResult {
                            job_id: job.id.clone(),
                            repo_url: job.repo_url.clone(),
                            sins: vec![],
                            duration_ms: 0,
                            error: Some(format!("Parse error: {e}")),
                        },
                    },
                    Err(e) => ScanJobResult {
                        job_id: job.id.clone(),
                        repo_url: job.repo_url.clone(),
                        sins: vec![],
                        duration_ms: 0,
                        error: Some(format!("Connection error: {e}")),
                    },
                };

                let _ = tx_clone.send(result);
            });
        }

        drop(tx);

        let mut results = Vec::new();
        while let Some(result) = rx.recv().await {
            results.push(result);
        }

        results
    }
}

/// Worker node HTTP server that accepts scan jobs and executes them locally.
pub async fn run_worker(addr: &str) -> anyhow::Result<()> {
    use axum::routing::{get, post};
    use axum::Router;

    let app = Router::new()
        .route("/scan", post(handle_scan_job))
        .route("/healthz", get(|| async { "ok" }));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("[velka-worker] Listening on {addr}");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_scan_job(axum::Json(job): axum::Json<ScanJob>) -> axum::Json<ScanJobResult> {
    let start = std::time::Instant::now();

    // Clone to temp dir and scan
    let result = execute_scan_job(&job).await;

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(sins) => axum::Json(ScanJobResult {
            job_id: job.id,
            repo_url: job.repo_url,
            sins,
            duration_ms,
            error: None,
        }),
        Err(e) => axum::Json(ScanJobResult {
            job_id: job.id,
            repo_url: job.repo_url,
            sins: vec![],
            duration_ms,
            error: Some(e.to_string()),
        }),
    }
}

async fn execute_scan_job(job: &ScanJob) -> anyhow::Result<Vec<SerializableSin>> {
    let tmp_dir = tempfile::tempdir()?;
    let clone_path = tmp_dir.path().to_path_buf();

    // Clone the repository
    let mut cmd = tokio::process::Command::new("git");
    cmd.arg("clone").arg("--depth").arg("1");

    if let Some(ref branch) = job.branch {
        cmd.arg("--branch").arg(branch);
    }

    cmd.arg(&job.repo_url).arg(&clone_path);

    let output = cmd.output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git clone failed: {stderr}");
    }

    // Run velka scan on the cloned repo
    let config = VelkaConfig::load().unwrap_or_default();
    let (sender, receiver) = crossbeam_channel::unbounded::<Sin>();

    let scan_path = clone_path.clone();
    let config_arc = Arc::new(config);
    let sender_clone = sender.clone();

    tokio::task::spawn_blocking(move || {
        let _ = crate::engine::investigate(&scan_path, &config_arc, &sender_clone);
    })
    .await?;

    drop(sender);

    let sins: Vec<SerializableSin> = receiver.iter().map(|s| SerializableSin::from(&s)).collect();

    Ok(sins)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serializable_sin_from() {
        let sin = Sin {
            path: "test.rs".into(),
            line_number: 10,
            snippet: "secret".into(),
            context: vec![],
            severity: crate::domain::Severity::Mortal,
            description: "test".into(),
            rule_id: "TEST".into(),
            commit_hash: None,
            verified: None,
            confidence: None,
            confidence_factors: None,
            confidence_level: None,
        };

        let serializable = SerializableSin::from(&sin);
        assert_eq!(serializable.path, "test.rs");
        assert_eq!(serializable.rule_id, "TEST");
        assert_eq!(serializable.severity, "Mortal");
    }
}
