//! # Registry Guard - Main Facade
//!
//! This module provides the primary interface to the Registry Guard system.
//! It coordinates all subsystems (canonicalization, Merkle tree, drift detection,
//! storage) into a cohesive API for tool schema management.
//!
//! ## Threat Model
//!
//! The Registry Guard provides defense-in-depth against:
//!
//! | Threat | Component | Defense |
//! |--------|-----------|---------|
//! | Rug Pull | Canonicalizer + Hash | Detect sudden schema changes |
//! | Shadow Server | Merkle Tree | Verify tool membership cryptographically |
//! | Schema Drift | Drift Detector | Categorize and alert on changes |
//! | Persistence Attacks | Sled Storage | Maintain verified state across restarts |
//!
//! ## Architecture
//!
//! ```text
//!                    ┌────────────────────┐
//!                    │   RegistryGuard    │
//!                    │      (Facade)      │
//!                    └─────────┬──────────┘
//!                              │
//!          ┌───────────┬───────┴───────┬───────────┐
//!          │           │               │           │
//!          ▼           ▼               ▼           ▼
//!    ┌──────────┐ ┌──────────┐  ┌──────────┐ ┌──────────┐
//!    │Canonical-│ │  Merkle  │  │  Drift   │ │ Storage  │
//!    │  izer    │ │   Tree   │  │ Detector │ │  (Sled)  │
//!    └──────────┘ └──────────┘  └──────────┘ └──────────┘
//! ```
//!
//! ## Usage Flow
//!
//! 1. **Initialization**: Open registry with database path
//! 2. **Registration**: Register tool schemas (stores hash + schema)
//! 3. **Verification**: Verify tools against registered versions
//! 4. **Drift Detection**: Analyze changes when verification fails
//! 5. **Proof Generation**: Generate Merkle proofs for distributed verification
//!
//! ## References
//!
//! - RFC 8785 - JSON Canonicalization Scheme
//! - Merkle, R. C. (1979) - Hash trees

use crate::canonicalize::hash_tool_schema;
use crate::drift::{detect_drift, new_tool_report};
use crate::merkle::MerkleTree;
use crate::models::{DriftReport, Hash, MerkleProof, RegistryError, Result, ToolSchema, VerifyResult};
use crate::storage::Storage;
use std::path::Path;

/// The main Registry Guard interface.
///
/// Coordinates all registry operations including tool registration,
/// verification, drift detection, and Merkle proof generation.
///
/// # Thread Safety
///
/// The `RegistryGuard` is not thread-safe due to the mutable Merkle tree.
/// Use external synchronization (e.g., `Mutex`) for concurrent access.
///
/// # Persistence
///
/// Tool registrations are persisted to a Sled database. The Merkle tree
/// is rebuilt on initialization from the stored data.
///
/// # Example
///
/// ```rust,no_run
/// use sentinel_registry::{RegistryGuard, ToolSchema, VerifyResult};
/// use serde_json::json;
///
/// // Create or open the registry
/// let mut registry = RegistryGuard::new("./registry.db").unwrap();
///
/// // Register a tool
/// let tool = ToolSchema {
///     name: "read_file".to_string(),
///     description: "Read a file".to_string(),
///     input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
///     output_schema: json!({"type": "string"}),
/// };
///
/// let hash = registry.register_tool(&tool).unwrap();
///
/// // Later, verify the tool hasn't changed
/// match registry.verify_tool(&tool) {
///     VerifyResult::Valid => println!("Tool verified"),
///     VerifyResult::Invalid { expected, actual } => {
///         println!("WARNING: Tool schema changed!");
///     }
///     VerifyResult::Unknown => println!("Tool not registered"),
/// }
/// ```
pub struct RegistryGuard {
    /// Persistent storage for schemas and hashes.
    storage: Storage,

    /// In-memory Merkle tree for proof generation.
    merkle_tree: MerkleTree,
}

impl RegistryGuard {
    /// Creates a new Registry Guard with persistent storage.
    ///
    /// Opens or creates a database at the specified path. On initialization,
    /// the Merkle tree is rebuilt from stored hashes to ensure consistency.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the database directory
    ///
    /// # Returns
    ///
    /// A new `RegistryGuard` instance.
    ///
    /// # Errors
    ///
    /// Returns `RegistryError::Database` if the database cannot be opened.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use sentinel_registry::RegistryGuard;
    ///
    /// let registry = RegistryGuard::new("./data/registry").unwrap();
    /// ```
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let storage = Storage::open(path)?;
        let mut merkle_tree = MerkleTree::new();

        // Rebuild Merkle tree from storage
        for name in storage.list_tools()? {
            if let Some(hash) = storage.load_hash(&name)? {
                merkle_tree.insert(&name, hash);
            }
        }

        Ok(RegistryGuard {
            storage,
            merkle_tree,
        })
    }

    /// Creates a temporary Registry Guard for testing.
    ///
    /// Uses an in-memory database that is discarded when the
    /// `RegistryGuard` is dropped.
    ///
    /// # Returns
    ///
    /// A new in-memory `RegistryGuard` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::RegistryGuard;
    ///
    /// let registry = RegistryGuard::temporary().unwrap();
    /// // Use for testing...
    /// ```
    pub fn temporary() -> Result<Self> {
        Ok(RegistryGuard {
            storage: Storage::temporary()?,
            merkle_tree: MerkleTree::new(),
        })
    }

    /// Registers a tool schema in the registry.
    ///
    /// The schema is canonicalized, hashed, stored in the database,
    /// and added to the Merkle tree. If the tool already exists,
    /// it will be updated (use `verify_tool` first to detect changes).
    ///
    /// # Arguments
    ///
    /// * `tool` - The tool schema to register
    ///
    /// # Returns
    ///
    /// The SHA-256 hash of the canonical schema representation.
    ///
    /// # Errors
    ///
    /// Returns `RegistryError::Database` if storage fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::{RegistryGuard, ToolSchema};
    /// use serde_json::json;
    ///
    /// let mut registry = RegistryGuard::temporary().unwrap();
    ///
    /// let tool = ToolSchema {
    ///     name: "example".to_string(),
    ///     description: "An example tool".to_string(),
    ///     input_schema: json!({}),
    ///     output_schema: json!({}),
    /// };
    ///
    /// let hash = registry.register_tool(&tool).unwrap();
    /// println!("Registered with hash: {:02x?}", hash);
    /// ```
    pub fn register_tool(&mut self, tool: &ToolSchema) -> Result<Hash> {
        let hash = hash_tool_schema(tool);

        self.storage.store_tool(tool, hash)?;
        self.merkle_tree.insert(&tool.name, hash);

        Ok(hash)
    }

    /// Verifies a tool schema against the registered version.
    ///
    /// Computes the hash of the provided schema and compares it
    /// with the stored hash. This is a fast, constant-time operation.
    ///
    /// # Arguments
    ///
    /// * `tool` - The tool schema to verify
    ///
    /// # Returns
    ///
    /// - `VerifyResult::Valid` if the schema matches
    /// - `VerifyResult::Invalid` if the schema differs (potential rug pull)
    /// - `VerifyResult::Unknown` if the tool is not registered
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::{RegistryGuard, ToolSchema, VerifyResult};
    /// use serde_json::json;
    ///
    /// let mut registry = RegistryGuard::temporary().unwrap();
    ///
    /// let tool = ToolSchema {
    ///     name: "test".to_string(),
    ///     description: "Test".to_string(),
    ///     input_schema: json!({}),
    ///     output_schema: json!({}),
    /// };
    ///
    /// // Not registered yet
    /// assert!(matches!(registry.verify_tool(&tool), VerifyResult::Unknown));
    ///
    /// // Register and verify
    /// registry.register_tool(&tool).unwrap();
    /// assert!(matches!(registry.verify_tool(&tool), VerifyResult::Valid));
    /// ```
    pub fn verify_tool(&self, tool: &ToolSchema) -> VerifyResult {
        let actual_hash = hash_tool_schema(tool);

        match self.storage.load_hash(&tool.name) {
            Ok(Some(expected_hash)) => {
                if expected_hash == actual_hash {
                    VerifyResult::Valid
                } else {
                    VerifyResult::Invalid {
                        expected: expected_hash,
                        actual: actual_hash,
                    }
                }
            }
            Ok(None) => VerifyResult::Unknown,
            Err(_) => VerifyResult::Unknown,
        }
    }

    /// Detects and categorizes drift between a tool and its registered version.
    ///
    /// Provides detailed analysis of what changed and the security severity.
    /// Use this when `verify_tool` returns `Invalid` to understand the changes.
    ///
    /// # Arguments
    ///
    /// * `tool` - The tool schema to analyze
    ///
    /// # Returns
    ///
    /// A `DriftReport` containing:
    /// - Drift level (None, Minor, Major, Critical)
    /// - List of specific changes
    /// - Hashes of both versions
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::{RegistryGuard, ToolSchema, DriftLevel};
    /// use serde_json::json;
    ///
    /// let mut registry = RegistryGuard::temporary().unwrap();
    ///
    /// let original = ToolSchema {
    ///     name: "tool".to_string(),
    ///     description: "A tool".to_string(),
    ///     input_schema: json!({}),
    ///     output_schema: json!({}),
    /// };
    ///
    /// registry.register_tool(&original).unwrap();
    ///
    /// let modified = ToolSchema {
    ///     name: "tool".to_string(),
    ///     description: "A modified tool".to_string(), // Changed
    ///     input_schema: json!({}),
    ///     output_schema: json!({}),
    /// };
    ///
    /// let report = registry.detect_drift(&modified);
    /// if report.level >= DriftLevel::Major {
    ///     println!("Security review needed: {:?}", report.changes);
    /// }
    /// ```
    pub fn detect_drift(&self, tool: &ToolSchema) -> DriftReport {
        match self.storage.load_tool(&tool.name) {
            Ok(Some((old_tool, _))) => detect_drift(&old_tool, tool),
            Ok(None) => new_tool_report(tool),
            Err(_) => new_tool_report(tool),
        }
    }

    /// Generates a Merkle proof for a registered tool.
    ///
    /// The proof can be used to verify that a tool is part of the
    /// registry without access to the full database.
    ///
    /// # Arguments
    ///
    /// * `tool_name` - The name of the tool to prove
    ///
    /// # Returns
    ///
    /// A `MerkleProof` if the tool exists, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::{RegistryGuard, ToolSchema};
    /// use sentinel_registry::merkle::MerkleTree;
    /// use serde_json::json;
    ///
    /// let mut registry = RegistryGuard::temporary().unwrap();
    ///
    /// let tool = ToolSchema {
    ///     name: "tool".to_string(),
    ///     description: "A tool".to_string(),
    ///     input_schema: json!({}),
    ///     output_schema: json!({}),
    /// };
    ///
    /// registry.register_tool(&tool).unwrap();
    ///
    /// if let Some(proof) = registry.get_merkle_proof("tool") {
    ///     let root = registry.get_root();
    ///     assert!(MerkleTree::verify_proof(&proof, &root));
    /// }
    /// ```
    pub fn get_merkle_proof(&mut self, tool_name: &str) -> Option<MerkleProof> {
        self.merkle_tree.get_proof(tool_name)
    }

    /// Returns the current Merkle root hash.
    ///
    /// The root hash represents the entire state of the registry.
    /// If the root changes, at least one tool registration has changed.
    ///
    /// # Returns
    ///
    /// The 32-byte Merkle root hash.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::RegistryGuard;
    ///
    /// let mut registry = RegistryGuard::temporary().unwrap();
    /// let initial_root = registry.get_root();
    ///
    /// // After registering tools, the root will change
    /// ```
    pub fn get_root(&mut self) -> Hash {
        self.merkle_tree.get_root()
    }

    /// Returns the hash for a specific tool.
    ///
    /// # Arguments
    ///
    /// * `tool_name` - The name of the tool
    ///
    /// # Returns
    ///
    /// The tool's hash if registered, `None` otherwise.
    pub fn get_tool_hash(&self, tool_name: &str) -> Option<Hash> {
        self.storage.load_hash(tool_name).ok().flatten()
    }

    /// Lists all registered tool names.
    ///
    /// # Returns
    ///
    /// A vector of registered tool names.
    ///
    /// # Errors
    ///
    /// Returns `RegistryError::Database` if reading fails.
    pub fn list_tools(&self) -> Result<Vec<String>> {
        self.storage.list_tools()
    }

    /// Checks if a tool is registered.
    ///
    /// # Arguments
    ///
    /// * `tool_name` - The name to check
    ///
    /// # Returns
    ///
    /// `true` if the tool exists, `false` otherwise.
    pub fn contains(&self, tool_name: &str) -> bool {
        self.storage.contains(tool_name).unwrap_or(false)
    }

    /// Removes a tool from the registry.
    ///
    /// # Arguments
    ///
    /// * `tool_name` - The name of the tool to remove
    ///
    /// # Returns
    ///
    /// `true` if the tool was removed, `false` if it didn't exist.
    ///
    /// # Errors
    ///
    /// Returns `RegistryError::Database` if removal fails.
    pub fn remove_tool(&mut self, tool_name: &str) -> Result<bool> {
        let removed = self.storage.remove_tool(tool_name)?;
        if removed {
            self.merkle_tree.remove(tool_name);
        }
        Ok(removed)
    }

    /// Returns the number of registered tools.
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    /// Returns true if no tools are registered.
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    /// Flushes pending writes to disk.
    ///
    /// Ensures all registrations are persisted before returning.
    pub fn flush(&self) -> Result<()> {
        self.storage.flush()?;
        Ok(())
    }
}

impl std::fmt::Debug for RegistryGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryGuard")
            .field("tools_count", &self.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tool(name: &str, desc: &str) -> ToolSchema {
        ToolSchema {
            name: name.to_string(),
            description: desc.to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "string"}),
        }
    }

    #[test]
    fn test_register_and_verify() {
        let mut registry = RegistryGuard::temporary().unwrap();
        let tool = make_tool("test", "A test tool");

        let hash = registry.register_tool(&tool).unwrap();
        assert_ne!(hash, [0u8; 32]);

        assert!(matches!(registry.verify_tool(&tool), VerifyResult::Valid));
    }

    #[test]
    fn test_verify_unknown() {
        let registry = RegistryGuard::temporary().unwrap();
        let tool = make_tool("unknown", "Not registered");

        assert!(matches!(registry.verify_tool(&tool), VerifyResult::Unknown));
    }

    #[test]
    fn test_verify_invalid() {
        let mut registry = RegistryGuard::temporary().unwrap();
        let original = make_tool("test", "Original description");

        registry.register_tool(&original).unwrap();

        let modified = make_tool("test", "Modified description");
        match registry.verify_tool(&modified) {
            VerifyResult::Invalid { expected, actual } => {
                assert_ne!(expected, actual);
            }
            _ => panic!("Expected Invalid result"),
        }
    }

    #[test]
    fn test_detect_drift() {
        let mut registry = RegistryGuard::temporary().unwrap();
        let original = make_tool("test", "Original");

        registry.register_tool(&original).unwrap();

        let modified = make_tool("test", "Modified description here");
        let report = registry.detect_drift(&modified);

        assert!(report.level >= crate::DriftLevel::Minor);
        assert!(!report.changes.is_empty());
    }

    #[test]
    fn test_merkle_proof() {
        let mut registry = RegistryGuard::temporary().unwrap();

        registry.register_tool(&make_tool("a", "Tool A")).unwrap();
        registry.register_tool(&make_tool("b", "Tool B")).unwrap();

        let root = registry.get_root();

        let proof_a = registry.get_merkle_proof("a").unwrap();
        assert!(MerkleTree::verify_proof(&proof_a, &root));

        let proof_b = registry.get_merkle_proof("b").unwrap();
        assert!(MerkleTree::verify_proof(&proof_b, &root));
    }

    #[test]
    fn test_root_changes() {
        let mut registry = RegistryGuard::temporary().unwrap();

        let root1 = registry.get_root();

        registry.register_tool(&make_tool("a", "A")).unwrap();
        let root2 = registry.get_root();

        registry.register_tool(&make_tool("b", "B")).unwrap();
        let root3 = registry.get_root();

        assert_ne!(root1, root2);
        assert_ne!(root2, root3);
    }

    #[test]
    fn test_list_and_contains() {
        let mut registry = RegistryGuard::temporary().unwrap();

        assert!(registry.is_empty());
        assert!(!registry.contains("test"));

        registry.register_tool(&make_tool("test", "Test")).unwrap();

        assert!(!registry.is_empty());
        assert!(registry.contains("test"));
        assert_eq!(registry.len(), 1);

        let tools = registry.list_tools().unwrap();
        assert!(tools.contains(&"test".to_string()));
    }

    #[test]
    fn test_remove() {
        let mut registry = RegistryGuard::temporary().unwrap();

        registry.register_tool(&make_tool("test", "Test")).unwrap();
        assert!(registry.contains("test"));

        let removed = registry.remove_tool("test").unwrap();
        assert!(removed);
        assert!(!registry.contains("test"));

        let removed_again = registry.remove_tool("test").unwrap();
        assert!(!removed_again);
    }

    #[test]
    fn test_get_tool_hash() {
        let mut registry = RegistryGuard::temporary().unwrap();
        let tool = make_tool("test", "Test");

        assert!(registry.get_tool_hash("test").is_none());

        let registered_hash = registry.register_tool(&tool).unwrap();
        let retrieved_hash = registry.get_tool_hash("test").unwrap();

        assert_eq!(registered_hash, retrieved_hash);
    }
}
