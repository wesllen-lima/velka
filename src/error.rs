use thiserror::Error;

#[derive(Error, Debug)]
pub enum VelkaError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid regex pattern in rule '{rule_id}': {message}")]
    InvalidPattern { rule_id: String, message: String },

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Path validation failed: {0}")]
    InvalidPath(String),

    #[error("Git operation failed")]
    Git(#[from] git2::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, VelkaError>;
