//! MCP Sentinel Core - Foundation types and traits for the security gateway

/// Core result type for sentinel operations
pub type Result<T> = std::result::Result<T, SentinelError>;

/// Core error type
#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Internal error: {0}")]
    Internal(String),
}
