//! # Core Data Models for Registry Guard
//!
//! This module defines the fundamental types used throughout the Registry Guard.
//! Each type is designed with security as a primary concern, ensuring type safety
//! and clear semantics for cryptographic operations.
//!
//! ## Threat Model
//!
//! The types in this module help defend against:
//!
//! - **Type Confusion**: Strong typing prevents mixing hashes with other byte arrays.
//! - **Incomplete Comparisons**: `VerifyResult` forces handling of all verification states.
//! - **Ambiguous Drift**: `DriftLevel` categorization ensures consistent response to changes.
//!
//! ## References
//!
//! - MCP Tool Schema specification
//! - NIST FIPS 180-4 for hash size (SHA-256 = 32 bytes)

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SHA-256 hash output size in bytes.
///
/// This constant is derived from NIST FIPS 180-4 which specifies
/// that SHA-256 produces a 256-bit (32-byte) digest.
pub const HASH_SIZE: usize = 32;

/// A 32-byte SHA-256 hash value.
///
/// This type alias provides semantic meaning to raw byte arrays,
/// making it clear when a value represents a cryptographic hash
/// rather than arbitrary data.
///
/// # Security Notes
///
/// - Constant-time comparison should be used when comparing hashes
///   to prevent timing attacks.
/// - Display implementations should use hex encoding for readability.
pub type Hash = [u8; HASH_SIZE];

/// An MCP tool schema definition.
///
/// Represents the complete schema for a tool as defined by the MCP specification.
/// This includes the tool's identity, human-readable description, and the
/// JSON Schema definitions for its inputs and outputs.
///
/// # Fields
///
/// - `name`: Unique identifier for the tool (e.g., "read_file", "execute_bash")
/// - `description`: Human-readable explanation of the tool's purpose
/// - `input_schema`: JSON Schema defining valid input parameters
/// - `output_schema`: JSON Schema defining the structure of outputs
///
/// # Example
///
/// ```rust
/// use sentinel_registry::ToolSchema;
/// use serde_json::json;
///
/// let schema = ToolSchema {
///     name: "search_files".to_string(),
///     description: "Search for files matching a pattern".to_string(),
///     input_schema: json!({
///         "type": "object",
///         "properties": {
///             "pattern": { "type": "string" },
///             "directory": { "type": "string" }
///         },
///         "required": ["pattern"]
///     }),
///     output_schema: json!({
///         "type": "array",
///         "items": { "type": "string" }
///     }),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSchema {
    /// Unique identifier for the tool.
    pub name: String,

    /// Human-readable description of what the tool does.
    pub description: String,

    /// JSON Schema defining the tool's input parameters.
    pub input_schema: serde_json::Value,

    /// JSON Schema defining the tool's output structure.
    pub output_schema: serde_json::Value,
}

/// Result of verifying a tool schema against the registry.
///
/// Represents the three possible outcomes when checking whether a tool's
/// current schema matches what was previously registered.
///
/// # Variants
///
/// - `Valid`: Schema matches exactly (hashes are identical)
/// - `Invalid`: Schema differs from registered version (possible rug pull)
/// - `Unknown`: Tool has never been registered
///
/// # Security Notes
///
/// An `Invalid` result should be treated as a potential security incident.
/// The expected and actual hashes are provided for forensic analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Schema matches the registered version exactly.
    Valid,

    /// Schema differs from the registered version.
    ///
    /// This indicates potential tampering or unauthorized modification.
    Invalid {
        /// The hash that was expected (from registry).
        expected: Hash,
        /// The hash that was computed (from provided schema).
        actual: Hash,
    },

    /// Tool is not present in the registry.
    ///
    /// This could indicate a new tool or an attempted injection.
    Unknown,
}

/// Severity level of detected schema drift.
///
/// Categorizes the magnitude of changes between the registered and
/// current version of a tool schema. Higher levels indicate more
/// significant security concerns.
///
/// # Variants
///
/// - `None`: No changes detected
/// - `Minor`: Cosmetic changes (whitespace, description wording)
/// - `Major`: Functional changes (parameter additions/removals)
/// - `Critical`: Fundamental changes (different tool behavior)
///
/// # Security Notes
///
/// Even `Minor` drift should be investigated in high-security environments,
/// as attackers may use incremental changes to avoid detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DriftLevel {
    /// No changes detected between versions.
    None,

    /// Minor changes that don't affect functionality.
    ///
    /// Examples:
    /// - Description wording changes
    /// - Added documentation
    /// - Optional parameter descriptions
    Minor,

    /// Major changes that affect how the tool is used.
    ///
    /// Examples:
    /// - New required parameters
    /// - Removed parameters
    /// - Changed parameter types
    Major,

    /// Critical changes indicating fundamental alteration.
    ///
    /// Examples:
    /// - Different tool purpose
    /// - Changed security properties
    /// - Incompatible input/output schemas
    Critical,
}

/// Detailed report of schema drift between versions.
///
/// Provides comprehensive information about what changed between the
/// registered and current version of a tool schema, enabling both
/// automated responses and human review.
///
/// # Fields
///
/// - `level`: Overall severity classification
/// - `changes`: Human-readable list of specific changes detected
/// - `old_hash`: Hash of the registered (expected) schema
/// - `new_hash`: Hash of the current (observed) schema
///
/// # Example
///
/// ```rust
/// use sentinel_registry::{DriftReport, DriftLevel};
///
/// let report = DriftReport {
///     level: DriftLevel::Major,
///     changes: vec![
///         "Added required parameter 'force'".to_string(),
///         "Changed description".to_string(),
///     ],
///     old_hash: Some([0u8; 32]),
///     new_hash: [0u8; 32],
/// };
///
/// if report.level >= DriftLevel::Major {
///     println!("Security review required: {:?}", report.changes);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftReport {
    /// Overall severity of the detected drift.
    pub level: DriftLevel,

    /// List of specific changes detected.
    pub changes: Vec<String>,

    /// Hash of the previously registered schema, if known.
    pub old_hash: Option<Hash>,

    /// Hash of the current schema.
    pub new_hash: Hash,
}

/// A node in the Merkle proof path.
///
/// Represents a single step in the proof from a leaf hash to the root.
/// Each node contains a sibling hash and indicates whether it should be
/// concatenated on the left or right during verification.
///
/// # Fields
///
/// - `hash`: The sibling hash at this level of the tree
/// - `is_left`: Whether this sibling is on the left (true) or right (false)
///
/// # References
///
/// - Merkle, R. C. (1979) - Original hash tree construction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofNode {
    /// The sibling hash at this tree level.
    pub hash: Hash,

    /// Whether this sibling is on the left of the path.
    pub is_left: bool,
}

/// Cryptographic proof of inclusion in the Merkle tree.
///
/// A Merkle proof allows efficient verification that a specific tool schema
/// is part of the registry without requiring access to all registered tools.
/// This is useful for distributed verification scenarios.
///
/// # Fields
///
/// - `leaf_hash`: Hash of the tool schema being proven
/// - `path`: Sequence of sibling hashes from leaf to root
/// - `root_hash`: Expected root hash for verification
///
/// # Security Notes
///
/// Proofs should be verified by recomputing the root hash from the leaf
/// using the path and comparing to a trusted root. The root must be
/// obtained through a secure channel.
///
/// # Example
///
/// ```rust
/// use sentinel_registry::merkle::MerkleTree;
///
/// // Proof verification is handled by the MerkleTree module
/// // See merkle.rs for the verify_proof function
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Hash of the leaf being proven.
    pub leaf_hash: Hash,

    /// Path of sibling hashes from leaf to root.
    pub path: Vec<MerkleProofNode>,

    /// Root hash at the time the proof was generated.
    pub root_hash: Hash,
}

/// Errors that can occur during registry operations.
///
/// Comprehensive error type covering all failure modes in the Registry Guard.
/// Each variant provides context for debugging and appropriate error handling.
///
/// # Variants
///
/// See individual variant documentation for specific error conditions.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Failed to open or create the database.
    #[error("Database error: {0}")]
    Database(#[from] sled::Error),

    /// Failed to serialize or deserialize data.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The requested tool was not found in the registry.
    #[error("Tool not found: {0}")]
    NotFound(String),

    /// A tool with this name already exists.
    #[error("Tool already registered: {0}")]
    AlreadyExists(String),

    /// The provided Merkle proof is invalid.
    #[error("Invalid Merkle proof")]
    InvalidProof,
}

/// Result type for registry operations.
pub type Result<T> = std::result::Result<T, RegistryError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drift_level_ordering() {
        assert!(DriftLevel::None < DriftLevel::Minor);
        assert!(DriftLevel::Minor < DriftLevel::Major);
        assert!(DriftLevel::Major < DriftLevel::Critical);
    }

    #[test]
    fn test_tool_schema_serialization() {
        let schema = ToolSchema {
            name: "test".to_string(),
            description: "Test tool".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "string"}),
        };

        let json = serde_json::to_string(&schema).unwrap();
        let parsed: ToolSchema = serde_json::from_str(&json).unwrap();

        assert_eq!(schema, parsed);
    }

    #[test]
    fn test_verify_result_variants() {
        let valid = VerifyResult::Valid;
        let invalid = VerifyResult::Invalid {
            expected: [0u8; 32],
            actual: [1u8; 32],
        };
        let unknown = VerifyResult::Unknown;

        assert_eq!(valid, VerifyResult::Valid);
        assert_ne!(invalid, VerifyResult::Valid);
        assert_ne!(unknown, VerifyResult::Valid);
    }
}
