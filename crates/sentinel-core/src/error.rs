//! Error types for MCP Sentinel Core.

use thiserror::Error;

/// Core error type for sentinel operations.
#[derive(Debug, Error)]
pub enum SentinelError {
    /// Schema verification failed (Registry Guard).
    #[error("Schema verification failed: {0}")]
    SchemaViolation(String),

    /// State monitoring detected an issue (State Monitor).
    #[error("State violation: {0}")]
    StateViolation(String),

    /// Council rejected the action (Cognitive Council).
    #[error("Council rejection: {0}")]
    CouncilRejection(String),

    /// Waluigi effect detected (alignment inversion).
    #[error("Waluigi effect detected: {0}")]
    WaluigiDetected(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Registry error passthrough.
    #[error("Registry error: {0}")]
    Registry(String),

    /// Monitor error passthrough.
    #[error("Monitor error: {0}")]
    Monitor(#[from] sentinel_monitor::MonitorError),

    /// Council error passthrough.
    #[error("Council error: {0}")]
    Council(#[from] sentinel_council::CouncilError),
}
