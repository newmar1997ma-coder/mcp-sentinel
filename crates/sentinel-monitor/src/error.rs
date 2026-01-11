//! Error types for the cycle detection module.
//!
//! Provides structured error handling for cycle detection operations.

use thiserror::Error;

/// Result type alias for monitor operations.
pub type Result<T> = std::result::Result<T, MonitorError>;

/// Errors that can occur during cycle detection and monitoring.
///
/// # Security Notes
///
/// Error messages are designed to provide useful debugging information
/// without leaking sensitive execution state to potential attackers.
#[derive(Debug, Error)]
pub enum MonitorError {
    /// Cycle detected in execution path.
    ///
    /// This is a security-critical error indicating potential infinite loop.
    #[error("cycle detected at step {step}: {description}")]
    CycleDetected {
        /// Step number where cycle was detected
        step: u64,
        /// Human-readable description of the cycle
        description: String,
    },

    /// Execution path exceeded maximum allowed length.
    ///
    /// Indicates potential resource exhaustion attack.
    #[error("execution path exceeded maximum length of {max_length}")]
    PathTooLong {
        /// Maximum allowed path length
        max_length: usize,
    },

    /// Invalid node state encountered.
    #[error("invalid node state: {0}")]
    InvalidState(String),

    /// Gas budget exhausted.
    ///
    /// Operation denied due to insufficient gas remaining.
    /// This is a security-critical error indicating resource limits enforced.
    #[error("gas exhausted: {operation} requires {required} gas, only {available} available")]
    GasExhausted {
        /// Gas units required for the operation
        required: u64,
        /// Gas units currently available
        available: u64,
        /// Description of the denied operation
        operation: String,
    },

    /// Context capacity exceeded.
    ///
    /// Indicates context flush is required to continue execution.
    #[error("context capacity exceeded: {current} frames exceeds limit of {limit}")]
    ContextOverflow {
        /// Current number of frames
        current: usize,
        /// Maximum allowed frames
        limit: usize,
    },
}
