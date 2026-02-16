use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::{
    Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DidSaveTextDocumentParams, InitializeParams, InitializeResult,
    InitializedParams, MessageType, NumberOrString, Position, Range, ServerCapabilities,
    ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind, Url,
};
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::config::VelkaConfig;
use crate::domain::{Severity, Sin};
use crate::engine::scanner::scan_content;

pub struct VelkaLspBackend {
    client: Client,
    config: Arc<RwLock<VelkaConfig>>,
    document_cache: Arc<RwLock<HashMap<Url, String>>>,
}

impl VelkaLspBackend {
    fn sin_to_diagnostic(sin: &Sin) -> Diagnostic {
        let severity = match sin.severity {
            Severity::Mortal => DiagnosticSeverity::ERROR,
            Severity::Venial => DiagnosticSeverity::WARNING,
        };

        let line = sin.line_number.saturating_sub(1) as u32;

        let mut message = format!("[{}] {}", sin.rule_id, sin.description);
        if let Some(confidence) = sin.confidence {
            use std::fmt::Write;
            let _ = write!(message, " (confidence: {:.0}%)", confidence * 100.0);
        }
        if let Some(level) = sin.confidence_level {
            use std::fmt::Write;
            let _ = write!(message, " [{level}]");
        }

        Diagnostic {
            range: Range {
                start: Position::new(line, 0),
                end: Position::new(line, u32::MAX),
            },
            severity: Some(severity),
            code: Some(NumberOrString::String(sin.rule_id.clone())),
            code_description: None,
            source: Some("velka".to_string()),
            message,
            related_information: None,
            tags: None,
            data: None,
        }
    }

    async fn diagnose(&self, uri: &Url) {
        let text = {
            let cache = self.document_cache.read().await;
            cache.get(uri).cloned()
        };

        let Some(text) = text else { return };

        let config = self.config.read().await;
        let Ok(sins) = scan_content(&text, &config) else {
            return;
        };

        let diagnostics: Vec<Diagnostic> = sins.iter().map(Self::sin_to_diagnostic).collect();

        self.client
            .publish_diagnostics(uri.clone(), diagnostics, None)
            .await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for VelkaLspBackend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "velka-lsp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "Velka LSP server initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        {
            let mut cache = self.document_cache.write().await;
            cache.insert(uri.clone(), params.text_document.text);
        }
        self.diagnose(&uri).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        if let Some(change) = params.content_changes.into_iter().last() {
            let mut cache = self.document_cache.write().await;
            cache.insert(uri.clone(), change.text);
        }
        self.diagnose(&uri).await;
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        self.diagnose(&params.text_document.uri).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        {
            let mut cache = self.document_cache.write().await;
            cache.remove(&uri);
        }
        self.client.publish_diagnostics(uri, vec![], None).await;
    }
}

/// Start the Velka LSP server on stdin/stdout.
pub async fn run_lsp() -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let config = VelkaConfig::load().unwrap_or_default();

    let (service, socket) = LspService::new(|client| VelkaLspBackend {
        client,
        config: Arc::new(RwLock::new(config)),
        document_cache: Arc::new(RwLock::new(HashMap::new())),
    });

    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(())
}
