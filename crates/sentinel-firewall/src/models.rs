//! # Core Types for the Semantic Firewall
//!
//! This module defines the fundamental data types used throughout the firewall
//! system for threat classification, scan results, and error handling.
//!
//! ## Threat Model
//!
//! The type system encodes our threat taxonomy based on:
//!
//! - **OWASP LLM Top 10 (2023)** - Industry-standard vulnerability classification
//! - **MITRE ATLAS** - Adversarial Threat Landscape for AI Systems
//! - **Academic Literature** - Zou et al., Greshake et al. prompt injection research
//!
//! Each [`ThreatType`] variant maps to a specific attack class with known
//! detection strategies and confidence calibration.
//!
//! ## Design Principles
//!
//! 1. **Exhaustive Classification** - All detected threats map to a specific variant
//! 2. **Confidence Calibration** - Every result includes a confidence score (0.0-1.0)
//! 3. **Actionable Results** - [`ScanResult`] enables clear allow/deny decisions
//! 4. **Serializable** - All types derive Serde traits for logging and audit trails
//!
//! ## References
//!
//! - OWASP LLM Top 10: <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
//! - MITRE ATLAS: <https://atlas.mitre.org/>

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Types of threats the firewall can detect.
///
/// This enum represents the taxonomy of adversarial attacks against LLM systems.
/// Each variant corresponds to a distinct attack methodology with specific
/// detection strategies.
///
/// # Variants
///
/// | Variant | Attack Class | Detection Method |
/// |---------|--------------|------------------|
/// | `Injection` | Direct prompt injection | Pattern matching |
/// | `Jailbreak` | System prompt extraction/bypass | Pattern + heuristics |
/// | `DataExfil` | Unauthorized data disclosure | Canary tokens |
/// | `Polyglot` | Multi-format exploit payloads | Format validation |
/// | `Stego` | Steganographic hidden data | CDR re-encoding |
/// | `HighEntropy` | Adversarial suffix (GCG) | Shannon entropy |
///
/// # Security Note
///
/// This taxonomy is not exhaustive. New attack vectors emerge regularly.
/// The firewall should be updated as new threats are documented in
/// academic literature and security advisories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatType {
    /// Direct prompt injection attempt.
    ///
    /// Classic attacks like "ignore previous instructions" that attempt to
    /// override system prompts with user-controlled instructions.
    ///
    /// Reference: Perez & Ribeiro, "Ignore This Title and HackAPrompt" (2023)
    Injection,

    /// Jailbreak or system prompt extraction attempt.
    ///
    /// Attacks designed to extract the system prompt, bypass safety guidelines,
    /// or trick the model into adopting a different persona (e.g., DAN).
    ///
    /// Reference: Shen et al., "Do Anything Now: Characterizing and Evaluating
    /// In-The-Wild Jailbreak Prompts on Large Language Models" (2023)
    Jailbreak,

    /// Data exfiltration attempt.
    ///
    /// Attempts to extract sensitive information, API keys, or internal
    /// system details through the model's outputs.
    DataExfil,

    /// Polyglot attack (multi-format exploit).
    ///
    /// Payloads that are valid in multiple contexts (e.g., valid JSON that
    /// is also valid JavaScript, or markdown that contains hidden HTML).
    Polyglot,

    /// Steganographic payload.
    ///
    /// Hidden data embedded in images, audio, or text using steganographic
    /// techniques. Detected through CDR re-encoding.
    Stego,

    /// High-entropy gibberish (GCG-style attack).
    ///
    /// Adversarial suffixes generated through gradient-based optimization
    /// that appear as random character sequences but can manipulate model
    /// behavior.
    ///
    /// Reference: Zou et al., "Universal and Transferable Adversarial Attacks
    /// on Aligned Language Models" (2023)
    HighEntropy,
}

impl ThreatType {
    /// Returns the OWASP LLM Top 10 category this threat maps to.
    ///
    /// # Returns
    ///
    /// The OWASP identifier (e.g., "LLM01") for the corresponding vulnerability.
    pub fn owasp_category(&self) -> &'static str {
        match self {
            ThreatType::Injection => "LLM01: Prompt Injection",
            ThreatType::Jailbreak => "LLM01: Prompt Injection",
            ThreatType::DataExfil => "LLM06: Sensitive Information Disclosure",
            ThreatType::Polyglot => "LLM01: Prompt Injection",
            ThreatType::Stego => "LLM01: Prompt Injection",
            ThreatType::HighEntropy => "LLM01: Prompt Injection",
        }
    }
}

/// Result of scanning input or output for threats.
///
/// The three-tier result system enables nuanced security decisions:
///
/// - **Safe**: No threats detected, proceed normally
/// - **Flagged**: Suspicious content, log and optionally alert but don't block
/// - **Blocked**: High-confidence threat, reject the request
///
/// # Confidence Scores
///
/// All non-safe results include a confidence score from 0.0 to 1.0:
///
/// | Range | Interpretation |
/// |-------|----------------|
/// | 0.0 - 0.5 | Low confidence, likely false positive |
/// | 0.5 - 0.8 | Medium confidence, review recommended |
/// | 0.8 - 1.0 | High confidence, likely true positive |
///
/// # Example
///
/// ```rust
/// use sentinel_firewall::{ScanResult, ThreatType};
///
/// fn handle_result(result: ScanResult) {
///     match result {
///         ScanResult::Safe => {
///             // Process normally
///         }
///         ScanResult::Flagged { threat, confidence, detail } => {
///             // Log for security review
///             eprintln!("FLAGGED: {:?} (conf: {:.2}): {}", threat, confidence, detail);
///         }
///         ScanResult::Blocked { threat, confidence, detail } => {
///             // Reject and alert
///             panic!("BLOCKED: {:?} - {}", threat, detail);
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanResult {
    /// Content is safe to process.
    ///
    /// No threats were detected. The content can proceed through the pipeline.
    Safe,

    /// Content blocked - immediate threat detected.
    ///
    /// The firewall has high confidence this is a genuine attack.
    /// The request should be rejected and the incident logged.
    ///
    /// # Fields
    ///
    /// * `threat` - The type of threat detected
    /// * `confidence` - Confidence score from 0.0 to 1.0
    /// * `detail` - Human-readable description of why this was blocked
    Blocked {
        threat: ThreatType,
        confidence: f64,
        detail: String,
    },

    /// Content flagged - suspicious but not blocked.
    ///
    /// The content shows signs of potential malicious intent but doesn't
    /// meet the threshold for blocking. Should be logged and reviewed.
    ///
    /// # Fields
    ///
    /// * `threat` - The type of threat suspected
    /// * `confidence` - Confidence score from 0.0 to 1.0
    /// * `detail` - Human-readable description of why this was flagged
    Flagged {
        threat: ThreatType,
        confidence: f64,
        detail: String,
    },
}

impl ScanResult {
    /// Check if result indicates safe content.
    ///
    /// # Returns
    ///
    /// `true` if no threats were detected.
    #[inline]
    pub fn is_safe(&self) -> bool {
        matches!(self, ScanResult::Safe)
    }

    /// Check if result indicates blocked content.
    ///
    /// # Returns
    ///
    /// `true` if a high-confidence threat was detected and blocked.
    #[inline]
    pub fn is_blocked(&self) -> bool {
        matches!(self, ScanResult::Blocked { .. })
    }

    /// Check if result indicates flagged content.
    ///
    /// # Returns
    ///
    /// `true` if suspicious content was detected but not blocked.
    #[inline]
    pub fn is_flagged(&self) -> bool {
        matches!(self, ScanResult::Flagged { .. })
    }

    /// Get the confidence score if a threat was detected.
    ///
    /// # Returns
    ///
    /// `Some(confidence)` for Blocked/Flagged results, `None` for Safe.
    pub fn confidence(&self) -> Option<f64> {
        match self {
            ScanResult::Safe => None,
            ScanResult::Blocked { confidence, .. } => Some(*confidence),
            ScanResult::Flagged { confidence, .. } => Some(*confidence),
        }
    }

    /// Get the threat type if a threat was detected.
    ///
    /// # Returns
    ///
    /// `Some(threat)` for Blocked/Flagged results, `None` for Safe.
    pub fn threat_type(&self) -> Option<ThreatType> {
        match self {
            ScanResult::Safe => None,
            ScanResult::Blocked { threat, .. } => Some(*threat),
            ScanResult::Flagged { threat, .. } => Some(*threat),
        }
    }
}

/// Errors that can occur during content sanitization (CDR).
///
/// The CDR engine may fail for various reasons. These errors are recoverable
/// and should trigger fallback behavior (e.g., rejecting the content entirely
/// rather than passing it through unsanitized).
///
/// # Security Note
///
/// When sanitization fails, the safe default is to reject the content.
/// Never pass unsanitized content through the pipeline.
#[derive(Debug, Error)]
pub enum SanitizeError {
    /// Input contains invalid UTF-8 sequences.
    ///
    /// This may indicate binary data disguised as text or encoding attacks.
    #[error("Invalid UTF-8 sequence")]
    InvalidUtf8,

    /// Content exceeds maximum allowed size.
    ///
    /// Large payloads may be used for denial-of-service attacks against
    /// the sanitization engine.
    #[error("Content too large: {size} bytes (max: {max})")]
    TooLarge {
        /// Actual size of the content
        size: usize,
        /// Maximum allowed size
        max: usize,
    },

    /// Content type is not supported for sanitization.
    ///
    /// The CDR engine doesn't have a sanitizer for this content type.
    /// The content should be rejected.
    #[error("Unsupported content type: {0}")]
    UnsupportedType(String),

    /// Generic sanitization failure.
    ///
    /// An unexpected error occurred during sanitization. The content
    /// should be rejected.
    #[error("Sanitization failed: {0}")]
    Failed(String),
}
