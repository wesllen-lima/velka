//! Kubernetes admission webhook for blocking resources that contain secrets.
//!
//! This module provides a ValidatingWebhookConfiguration-compatible HTTP server
//! that intercepts Kubernetes API requests and scans manifests (Pods, Deployments, etc.)
//! for leaked credentials using Velka's rule engine.
//!
//! # Usage
//!
//! ```bash
//! # Plain HTTP (development)
//! velka k8s webhook --addr 0.0.0.0:8443
//!
//! # TLS (production)
//! velka k8s webhook --addr 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem
//! ```

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::config::VelkaConfig;
use crate::engine::scan_content;

/// Incoming `AdmissionReview` from the Kubernetes API server (v1).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReview {
    pub api_version: Option<String>,
    pub kind: Option<String>,
    pub request: Option<AdmissionRequest>,
}

/// The request payload within an `AdmissionReview`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
    pub uid: String,
    pub object: serde_json::Value,
}

/// Outgoing `AdmissionReview` response sent back to the API server.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionResponseReview {
    pub api_version: String,
    pub kind: String,
    pub response: AdmissionResponse,
}

/// The response payload: `allowed` + optional denial reason.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionResponse {
    pub uid: String,
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AdmissionStatus>,
}

/// HTTP-style status code and message for denied admissions.
#[derive(Debug, Serialize)]
pub struct AdmissionStatus {
    pub code: u16,
    pub message: String,
}

struct K8sState {
    config: VelkaConfig,
}

/// Start the K8s admission webhook server on the given address.
pub async fn run_admission_webhook(
    addr: &str,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
) -> anyhow::Result<()> {
    let config = VelkaConfig::load()?;
    let state = Arc::new(K8sState { config });

    let app = Router::new()
        .route("/validate", post(handle_admission))
        .route("/healthz", axum::routing::get(healthz))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    eprintln!("[velka-k8s] Admission webhook listening on {addr}");

    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let rustls_config = build_tls_config(cert_path, key_path)?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(rustls_config));

        loop {
            let (stream, _peer) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                        let service = hyper_util::service::TowerToHyperService::new(app);
                        let _ = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, service)
                        .await;
                    }
                    Err(e) => {
                        eprintln!("[velka-k8s] TLS accept error: {e}");
                    }
                }
            });
        }
    } else {
        axum::serve(listener, app).await?;
    }

    Ok(())
}

fn build_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::fs;
    use std::io::BufReader;

    let cert_pem = fs::read(cert_path)?;
    let key_pem = fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(&cert_pem[..]))
            .filter_map(std::result::Result::ok)
            .collect();

    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(&key_pem[..]))?
            .ok_or_else(|| anyhow::anyhow!("No private key found in {key_path}"))?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn handle_admission(
    State(state): State<Arc<K8sState>>,
    Json(review): Json<AdmissionReview>,
) -> (StatusCode, Json<AdmissionResponseReview>) {
    let Some(request) = review.request else {
        return (
            StatusCode::BAD_REQUEST,
            Json(AdmissionResponseReview {
                api_version: "admission.k8s.io/v1".into(),
                kind: "AdmissionReview".into(),
                response: AdmissionResponse {
                    uid: String::new(),
                    allowed: false,
                    status: Some(AdmissionStatus {
                        code: 400,
                        message: "Missing request in AdmissionReview".into(),
                    }),
                },
            }),
        );
    };

    let uid = request.uid.clone();
    let manifest_yaml = serde_json::to_string_pretty(&request.object).unwrap_or_default();

    let Ok(sins) = scan_content(&manifest_yaml, &state.config) else {
        return (
            StatusCode::OK,
            Json(AdmissionResponseReview {
                api_version: "admission.k8s.io/v1".into(),
                kind: "AdmissionReview".into(),
                response: AdmissionResponse {
                    uid,
                    allowed: true,
                    status: None,
                },
            }),
        );
    };

    let mortal_sins: Vec<_> = sins
        .iter()
        .filter(|s| s.severity == crate::domain::Severity::Mortal)
        .collect();

    if mortal_sins.is_empty() {
        (
            StatusCode::OK,
            Json(AdmissionResponseReview {
                api_version: "admission.k8s.io/v1".into(),
                kind: "AdmissionReview".into(),
                response: AdmissionResponse {
                    uid,
                    allowed: true,
                    status: None,
                },
            }),
        )
    } else {
        let descriptions: Vec<String> = mortal_sins
            .iter()
            .map(|s| format!("{} (line {}): {}", s.rule_id, s.line_number, s.description))
            .collect();

        let message = format!(
            "Velka blocked this resource: {} secret(s) detected in manifest. {}",
            mortal_sins.len(),
            descriptions.join("; ")
        );

        (
            StatusCode::OK,
            Json(AdmissionResponseReview {
                api_version: "admission.k8s.io/v1".into(),
                kind: "AdmissionReview".into(),
                response: AdmissionResponse {
                    uid,
                    allowed: false,
                    status: Some(AdmissionStatus { code: 403, message }),
                },
            }),
        )
    }
}

/// Scan raw YAML manifests for secrets and return any findings.
pub fn scan_k8s_manifest(yaml_content: &str) -> anyhow::Result<Vec<crate::domain::Sin>> {
    let config = VelkaConfig::load()?;
    let sins = scan_content(yaml_content, &config)?;
    Ok(sins)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_manifest_with_secret() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    env:
    - name: AWS_KEY
      value: "AKIA0000000000000000"
"#;
        let sins = scan_k8s_manifest(yaml).unwrap();
        assert!(!sins.is_empty());
        assert!(sins.iter().any(|s| s.rule_id == "AWS_ACCESS_KEY"));
    }

    #[test]
    fn test_scan_clean_manifest() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: clean-pod
spec:
  containers:
  - name: app
    image: nginx:latest
"#;
        let sins = scan_k8s_manifest(yaml).unwrap();
        assert!(sins.is_empty());
    }
}
