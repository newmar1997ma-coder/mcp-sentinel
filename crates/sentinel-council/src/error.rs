//! Error types for the Cognitive Council.
//!
//! Defines errors that can occur during council evaluation,
//! consensus voting, and Waluigi detection.

use thiserror::Error;

/// Errors that can occur during council operations.
#[derive(Debug, Error)]
pub enum CouncilError {
    /// An evaluator failed to produce a vote.
    #[error("Evaluator '{0}' failed to vote: {1}")]
    EvaluatorFailure(String, String),

    /// Consensus could not be reached.
    #[error("Consensus failure: {0}")]
    ConsensusFailure(String),

    /// Waluigi detection encountered an error.
    #[error("Waluigi detection error: {0}")]
    WaluigiDetectionError(String),

    /// The action proposal is malformed.
    #[error("Invalid action proposal: {0}")]
    InvalidProposal(String),

    /// Internal council error.
    #[error("Internal council error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluator_failure_display() {
        let err = CouncilError::EvaluatorFailure(
            "Deontologist".to_string(),
            "timeout".to_string(),
        );
        assert!(err.to_string().contains("Deontologist"));
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_consensus_failure_display() {
        let err = CouncilError::ConsensusFailure("deadlock".to_string());
        assert!(err.to_string().contains("deadlock"));
    }

    #[test]
    fn test_waluigi_error_display() {
        let err = CouncilError::WaluigiDetectionError("pattern mismatch".to_string());
        assert!(err.to_string().contains("pattern mismatch"));
    }

    #[test]
    fn test_invalid_proposal_display() {
        let err = CouncilError::InvalidProposal("empty action".to_string());
        assert!(err.to_string().contains("empty action"));
    }

    #[test]
    fn test_internal_error_display() {
        let err = CouncilError::Internal("unexpected state".to_string());
        assert!(err.to_string().contains("unexpected state"));
    }
}
