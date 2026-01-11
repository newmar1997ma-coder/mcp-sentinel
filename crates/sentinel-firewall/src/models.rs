//! Core types for the semantic firewall

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Types of threats the firewall can detect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatType {
    /// Direct prompt injection attempt
    Injection,
    /// Jailbreak/system prompt extraction
    Jailbreak,
    /// Data exfiltration attempt
    DataExfil,
    /// Polyglot attack (multi-format exploit)
    Polyglot,
    /// Steganographic payload
    Stego,
    /// High-entropy gibberish (GCG-style)
    HighEntropy,
}

/// Result of scanning input or output
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanResult {
    /// Content is safe to process
    Safe,
    /// Content blocked - immediate threat
    Blocked {
        threat: ThreatType,
        confidence: f64,
        detail: String,
    },
    /// Content flagged - suspicious but not blocked
    Flagged {
        threat: ThreatType,
        confidence: f64,
        detail: String,
    },
}

impl ScanResult {
    /// Check if result is safe
    pub fn is_safe(&self) -> bool {
        matches!(self, ScanResult::Safe)
    }

    /// Check if result is blocked
    pub fn is_blocked(&self) -> bool {
        matches!(self, ScanResult::Blocked { .. })
    }

    /// Check if result is flagged
    pub fn is_flagged(&self) -> bool {
        matches!(self, ScanResult::Flagged { .. })
    }
}

/// Errors during content sanitization
#[derive(Debug, Error)]
pub enum SanitizeError {
    #[error("Invalid UTF-8 sequence")]
    InvalidUtf8,
    #[error("Content too large: {size} bytes (max: {max})")]
    TooLarge { size: usize, max: usize },
    #[error("Unsupported content type: {0}")]
    UnsupportedType(String),
    #[error("Sanitization failed: {0}")]
    Failed(String),
}
