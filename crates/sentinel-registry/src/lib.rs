//! # Sentinel Registry Guard - Schema Integrity Verification
//!
//! The Registry Guard protects MCP deployments from tool schema tampering through
//! cryptographic verification using Merkle trees. It detects both sudden changes
//! (rug pulls) and gradual drift (shadow servers) by maintaining a verified record
//! of tool definitions.
//!
//! ## Purpose
//!
//! This crate implements four core security capabilities:
//!
//! 1. **RFC 8785 Canonicalization** - Deterministic JSON serialization ensuring
//!    identical schemas produce identical hashes regardless of key ordering.
//!
//! 2. **Merkle Tree Verification** - Efficient cryptographic proofs that a tool
//!    schema exists in the registry without exposing the entire database.
//!
//! 3. **Schema Drift Detection** - Identification and categorization of changes
//!    between registered and observed tool definitions.
//!
//! 4. **Persistent Registry** - Sled-backed storage for tool schemas and their
//!    cryptographic hashes, surviving restarts and enabling audit trails.
//!
//! ## Threat Model
//!
//! The Registry Guard defends against the following attack patterns:
//!
//! | Threat | Description | Defense |
//! |--------|-------------|---------|
//! | Rug Pull | Server suddenly changes tool behavior | Hash mismatch detection |
//! | Shadow Server | Attacker substitutes malicious server | Merkle root verification |
//! | Schema Drift | Gradual unauthorized modifications | Drift categorization |
//! | Replay Attack | Old schema presented as current | Merkle proof freshness |
//! | Hash Collision | Crafted schemas with same hash | SHA-256 collision resistance |
//! | Key Reordering | Schema changes via JSON key order | RFC 8785 canonicalization |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        REGISTRY GUARD                               │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  ┌───────────────────┐              ┌─────────────────────────┐    │
//! │  │   CANONICALIZER   │              │      MERKLE TREE        │    │
//! │  │                   │              │                         │    │
//! │  │  RFC 8785 JSON    │    hash      │   ┌───────────────┐    │    │
//! │  │  Normalization    │───────────▶  │   │   Root Hash   │    │    │
//! │  │                   │              │   └───────┬───────┘    │    │
//! │  │  • Sort keys      │              │           │            │    │
//! │  │  • Normalize nums │              │     ┌─────┴─────┐      │    │
//! │  │  • Minimal escape │              │     │           │      │    │
//! │  └───────────────────┘              │   ┌─┴─┐       ┌─┴─┐    │    │
//! │                                     │   │ H │       │ H │    │    │
//! │                                     │   └─┬─┘       └─┬─┘    │    │
//! │                                     │  ┌──┴──┐     ┌──┴──┐   │    │
//! │                                     │  │leaf1│     │leaf2│   │    │
//! │                                     │  └─────┘     └─────┘   │    │
//! │                                     └─────────────────────────┘    │
//! │                                                                     │
//! │  ┌───────────────────┐              ┌─────────────────────────┐    │
//! │  │  DRIFT DETECTOR   │              │    SLED STORAGE         │    │
//! │  │                   │              │                         │    │
//! │  │  Compare schemas  │◀────────────▶│  • Tool schemas         │    │
//! │  │  Categorize:      │              │  • Hash records         │    │
//! │  │  • None           │              │  • Merkle nodes         │    │
//! │  │  • Minor          │              │  • Audit trail          │    │
//! │  │  • Major          │              │                         │    │
//! │  │  • Critical       │              │  Persistent, ACID       │    │
//! │  └───────────────────┘              └─────────────────────────┘    │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## How It Works
//!
//! ### Registration Flow
//!
//! 1. Tool schema arrives (JSON with name, description, input/output schemas)
//! 2. Canonicalizer normalizes JSON per RFC 8785 (deterministic key ordering)
//! 3. SHA-256 hash computed from canonical form
//! 4. Hash inserted as leaf in Merkle tree
//! 5. Schema and hash persisted to Sled database
//! 6. Merkle root updated
//!
//! ### Verification Flow
//!
//! 1. Tool presents its schema for verification
//! 2. Canonicalizer normalizes the presented schema
//! 3. SHA-256 hash computed
//! 4. Hash compared against stored record
//! 5. If match: Valid (schema unchanged)
//! 6. If mismatch: Drift detector categorizes the difference
//!
//! ## References
//!
//! This implementation builds on foundational cryptographic research:
//!
//! - **RFC 8785 (2020)** - "JSON Canonicalization Scheme (JCS)"
//!   Defines deterministic JSON serialization for cryptographic hashing.
//!   <https://www.rfc-editor.org/rfc/rfc8785>
//!
//! - **Merkle, R. C. (1979)** - "Secrecy, Authentication, and Public Key Systems"
//!   Introduces hash trees for efficient verification in distributed systems.
//!   Stanford Ph.D. thesis. <https://www.ralphmerkle.com/papers/Thesis1979.pdf>
//!
//! - **Merkle, R. C. (1987)** - "A Digital Signature Based on a Conventional
//!   Encryption Function" - Practical Merkle tree construction for signatures.
//!   CRYPTO '87. <https://doi.org/10.1007/3-540-48184-2_32>
//!
//! - **NIST FIPS 180-4** - "Secure Hash Standard (SHS)" - SHA-256 specification.
//!   <https://csrc.nist.gov/publications/detail/fips/180/4/final>
//!
//! - **Sled Documentation** - Embedded database for persistent storage.
//!   <https://sled.rs/>
//!
//! ## Usage
//!
//! ```rust,no_run
//! use sentinel_registry::{RegistryGuard, ToolSchema, VerifyResult, DriftLevel};
//!
//! // Initialize the registry with a database path
//! let mut registry = RegistryGuard::new("./registry.db").unwrap();
//!
//! // Register a tool schema
//! let tool = ToolSchema {
//!     name: "read_file".to_string(),
//!     description: "Read contents of a file".to_string(),
//!     input_schema: serde_json::json!({
//!         "type": "object",
//!         "properties": {
//!             "path": { "type": "string" }
//!         }
//!     }),
//!     output_schema: serde_json::json!({
//!         "type": "string"
//!     }),
//! };
//!
//! let hash = registry.register_tool(&tool).unwrap();
//! println!("Registered with hash: {:?}", hash);
//!
//! // Verify the tool hasn't changed
//! match registry.verify_tool(&tool) {
//!     VerifyResult::Valid => println!("Tool verified!"),
//!     VerifyResult::Invalid { expected, actual } => {
//!         println!("HASH MISMATCH - possible rug pull!");
//!         println!("Expected: {:?}", expected);
//!         println!("Actual: {:?}", actual);
//!     }
//!     VerifyResult::Unknown => println!("Tool not in registry"),
//! }
//!
//! // Check for drift in a modified schema
//! let modified_tool = ToolSchema {
//!     name: "read_file".to_string(),
//!     description: "Read and return file contents".to_string(), // Changed!
//!     input_schema: tool.input_schema.clone(),
//!     output_schema: tool.output_schema.clone(),
//! };
//!
//! let drift = registry.detect_drift(&modified_tool);
//! match drift.level {
//!     DriftLevel::None => println!("No changes detected"),
//!     DriftLevel::Minor => println!("Minor changes: {:?}", drift.changes),
//!     DriftLevel::Major => println!("Major changes detected!"),
//!     DriftLevel::Critical => println!("CRITICAL: Schema fundamentally altered!"),
//! }
//!
//! // Get a Merkle proof for a specific tool
//! if let Some(proof) = registry.get_merkle_proof("read_file") {
//!     println!("Merkle proof: {:?}", proof);
//!     println!("Registry root: {:?}", registry.get_root());
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - **Hash Algorithm**: Uses SHA-256 which provides 128-bit security against
//!   collision attacks. This is sufficient for integrity verification.
//!
//! - **Canonicalization**: RFC 8785 ensures that semantically identical JSON
//!   documents produce identical canonical forms. This prevents attacks based
//!   on key reordering or whitespace manipulation.
//!
//! - **Storage Security**: The Sled database should be stored on encrypted
//!   storage with appropriate access controls. The registry itself does not
//!   encrypt data at rest.
//!
//! - **Time-of-Check to Time-of-Use**: Verification results are point-in-time.
//!   Between verification and use, a schema could theoretically change.
//!   For high-security deployments, consider re-verification at use time.

pub mod canonicalize;
pub mod drift;
pub mod merkle;
pub mod models;
pub mod registry;
pub mod storage;

pub use models::{DriftLevel, DriftReport, Hash, ToolSchema, VerifyResult};
pub use registry::RegistryGuard;

#[cfg(test)]
mod tests;
