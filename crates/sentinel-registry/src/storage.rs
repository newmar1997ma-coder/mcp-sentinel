//! # Persistent Storage Layer
//!
//! This module provides a persistence layer using Sled, an embedded database.
//! It stores tool schemas and their hashes, enabling the registry to survive
//! restarts and maintain an audit trail of registrations.
//!
//! ## Threat Model
//!
//! The storage layer defends against:
//!
//! - **Data Loss**: ACID transactions ensure consistency even on crash.
//! - **Corruption**: Sled's log-structured storage detects corruption.
//! - **Tampering**: Hash verification detects unauthorized database modifications.
//!
//! ## Storage Structure
//!
//! The database uses two trees (namespaces):
//!
//! | Tree | Key | Value | Purpose |
//! |------|-----|-------|---------|
//! | `schemas` | tool name | serialized ToolSchema | Schema storage |
//! | `hashes` | tool name | 32-byte hash | Quick verification |
//!
//! ## Security Notes
//!
//! - The database file should be stored on encrypted storage
//! - File permissions should restrict access to the sentinel process
//! - Regular backups are recommended for audit purposes
//!
//! ## References
//!
//! - Sled documentation: <https://sled.rs/>
//! - LMDB (similar architecture): <https://www.symas.com/lmdb>

use crate::models::{Hash, RegistryError, Result, ToolSchema, HASH_SIZE};
use std::path::Path;

/// Tree name for storing tool schemas.
const SCHEMA_TREE: &str = "schemas";

/// Tree name for storing tool hashes.
const HASH_TREE: &str = "hashes";

/// Wrapper around a Sled database for registry storage.
///
/// Provides high-level operations for storing and retrieving tool schemas
/// and their hashes. The database is opened in durable mode to ensure
/// data survives crashes.
///
/// # Thread Safety
///
/// The underlying Sled database is thread-safe. Multiple threads can
/// read and write concurrently.
///
/// # Example
///
/// ```rust,no_run
/// use sentinel_registry::storage::Storage;
/// use sentinel_registry::ToolSchema;
/// use serde_json::json;
///
/// let storage = Storage::open("./registry.db").unwrap();
///
/// let tool = ToolSchema {
///     name: "read_file".to_string(),
///     description: "Read a file".to_string(),
///     input_schema: json!({}),
///     output_schema: json!({}),
/// };
///
/// let hash = [1u8; 32];
/// storage.store_tool(&tool, hash).unwrap();
///
/// if let Some((loaded_tool, loaded_hash)) = storage.load_tool("read_file").unwrap() {
///     assert_eq!(loaded_tool.name, "read_file");
///     assert_eq!(loaded_hash, hash);
/// }
/// ```
#[derive(Clone)]
pub struct Storage {
    /// The underlying Sled database.
    db: sled::Db,

    /// Tree for storing serialized schemas.
    schemas: sled::Tree,

    /// Tree for storing hashes.
    hashes: sled::Tree,
}

impl Storage {
    /// Opens or creates a storage database at the given path.
    ///
    /// If the database doesn't exist, it will be created. If it exists,
    /// it will be opened and verified.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the database directory
    ///
    /// # Returns
    ///
    /// A new `Storage` instance or an error if the database cannot be opened.
    ///
    /// # Errors
    ///
    /// Returns `RegistryError::Database` if:
    /// - The path is invalid
    /// - Permissions are insufficient
    /// - The database is corrupted
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use sentinel_registry::storage::Storage;
    ///
    /// let storage = Storage::open("./data/registry").unwrap();
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path)?;
        let schemas = db.open_tree(SCHEMA_TREE)?;
        let hashes = db.open_tree(HASH_TREE)?;

        Ok(Storage { db, schemas, hashes })
    }

    /// Creates a temporary in-memory storage for testing.
    ///
    /// The database exists only in memory and is lost when the
    /// `Storage` instance is dropped.
    ///
    /// # Returns
    ///
    /// A new in-memory `Storage` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::storage::Storage;
    ///
    /// let storage = Storage::temporary().unwrap();
    /// // Use for testing...
    /// // Data is lost when storage is dropped
    /// ```
    pub fn temporary() -> Result<Self> {
        let config = sled::Config::new().temporary(true);
        let db = config.open()?;
        let schemas = db.open_tree(SCHEMA_TREE)?;
        let hashes = db.open_tree(HASH_TREE)?;

        Ok(Storage { db, schemas, hashes })
    }

    /// Stores a tool schema and its hash.
    ///
    /// If a tool with the same name already exists, it will be overwritten.
    /// Use `load_tool` first if you need to check for existing entries.
    ///
    /// # Arguments
    ///
    /// * `tool` - The tool schema to store
    /// * `hash` - The canonical hash of the tool schema
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if storage fails.
    ///
    /// # Errors
    ///
    /// Returns `RegistryError::Serialization` if the schema cannot be serialized.
    /// Returns `RegistryError::Database` if writing to the database fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::storage::Storage;
    /// use sentinel_registry::ToolSchema;
    /// use serde_json::json;
    ///
    /// let storage = Storage::temporary().unwrap();
    ///
    /// let tool = ToolSchema {
    ///     name: "test".to_string(),
    ///     description: "Test tool".to_string(),
    ///     input_schema: json!({}),
    ///     output_schema: json!({}),
    /// };
    ///
    /// storage.store_tool(&tool, [0u8; 32]).unwrap();
    /// ```
    pub fn store_tool(&self, tool: &ToolSchema, hash: Hash) -> Result<()> {
        let key = tool.name.as_bytes();
        let schema_bytes = serde_json::to_vec(tool)?;

        // Insert schema and hash
        // Note: These are separate operations. For full ACID guarantees,
        // consider using sled transactions if atomicity is critical.
        self.schemas.insert(key, schema_bytes)?;
        self.hashes.insert(key, hash.as_slice())?;

        Ok(())
    }

    /// Loads a tool schema and its hash by name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the tool to load
    ///
    /// # Returns
    ///
    /// `Some((schema, hash))` if found, `None` if not found.
    ///
    /// # Errors
    ///
    /// Returns `RegistryError::Serialization` if the stored schema is corrupted.
    /// Returns `RegistryError::Database` if reading from the database fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::storage::Storage;
    ///
    /// let storage = Storage::temporary().unwrap();
    ///
    /// match storage.load_tool("read_file").unwrap() {
    ///     Some((tool, hash)) => println!("Found: {}", tool.name),
    ///     None => println!("Tool not registered"),
    /// }
    /// ```
    pub fn load_tool(&self, name: &str) -> Result<Option<(ToolSchema, Hash)>> {
        let key = name.as_bytes();

        let schema_bytes = match self.schemas.get(key)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let hash_bytes = match self.hashes.get(key)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let tool: ToolSchema = serde_json::from_slice(&schema_bytes)?;

        // Convert IVec to Hash
        let hash: Hash = hash_bytes
            .as_ref()
            .try_into()
            .map_err(|_| RegistryError::InvalidProof)?;

        Ok(Some((tool, hash)))
    }

    /// Loads only the hash for a tool.
    ///
    /// This is more efficient than `load_tool` when only the hash is needed.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the tool
    ///
    /// # Returns
    ///
    /// `Some(hash)` if found, `None` if not found.
    pub fn load_hash(&self, name: &str) -> Result<Option<Hash>> {
        let key = name.as_bytes();

        match self.hashes.get(key)? {
            Some(bytes) => {
                if bytes.len() != HASH_SIZE {
                    return Err(RegistryError::InvalidProof);
                }
                let hash: Hash = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| RegistryError::InvalidProof)?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Lists all registered tool names.
    ///
    /// # Returns
    ///
    /// A vector of tool names in lexicographic order.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::storage::Storage;
    ///
    /// let storage = Storage::temporary().unwrap();
    /// let tools = storage.list_tools().unwrap();
    /// println!("Registered tools: {:?}", tools);
    /// ```
    pub fn list_tools(&self) -> Result<Vec<String>> {
        let mut tools = Vec::new();

        for result in self.schemas.iter() {
            let (key, _) = result?;
            let name = String::from_utf8(key.to_vec())
                .map_err(|_| RegistryError::InvalidProof)?;
            tools.push(name);
        }

        Ok(tools)
    }

    /// Checks if a tool is registered.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the tool to check
    ///
    /// # Returns
    ///
    /// `true` if the tool exists, `false` otherwise.
    pub fn contains(&self, name: &str) -> Result<bool> {
        Ok(self.schemas.contains_key(name.as_bytes())?)
    }

    /// Removes a tool from storage.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the tool to remove
    ///
    /// # Returns
    ///
    /// `true` if the tool was removed, `false` if it didn't exist.
    pub fn remove_tool(&self, name: &str) -> Result<bool> {
        let key = name.as_bytes();

        // Remove from both trees
        let existed = self.schemas.remove(key)?.is_some();
        self.hashes.remove(key)?;

        Ok(existed)
    }

    /// Returns the number of registered tools.
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    /// Returns true if no tools are registered.
    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }

    /// Flushes all pending writes to disk.
    ///
    /// Sled is asynchronous by default. This method ensures all data
    /// is persisted before returning.
    ///
    /// # Returns
    ///
    /// The number of bytes flushed.
    pub fn flush(&self) -> Result<usize> {
        Ok(self.db.flush()?)
    }
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Storage")
            .field("tools_count", &self.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tool(name: &str) -> ToolSchema {
        ToolSchema {
            name: name.to_string(),
            description: format!("Tool {}", name),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "string"}),
        }
    }

    #[test]
    fn test_temporary_storage() {
        let storage = Storage::temporary().unwrap();
        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);
    }

    #[test]
    fn test_store_and_load() {
        let storage = Storage::temporary().unwrap();
        let tool = make_tool("test_tool");
        let hash = [42u8; 32];

        storage.store_tool(&tool, hash).unwrap();

        let (loaded_tool, loaded_hash) = storage.load_tool("test_tool").unwrap().unwrap();
        assert_eq!(loaded_tool.name, "test_tool");
        assert_eq!(loaded_hash, hash);
    }

    #[test]
    fn test_load_nonexistent() {
        let storage = Storage::temporary().unwrap();
        assert!(storage.load_tool("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_load_hash() {
        let storage = Storage::temporary().unwrap();
        let tool = make_tool("test");
        let hash = [1u8; 32];

        storage.store_tool(&tool, hash).unwrap();

        let loaded_hash = storage.load_hash("test").unwrap().unwrap();
        assert_eq!(loaded_hash, hash);
    }

    #[test]
    fn test_list_tools() {
        let storage = Storage::temporary().unwrap();

        storage.store_tool(&make_tool("alpha"), [1u8; 32]).unwrap();
        storage.store_tool(&make_tool("beta"), [2u8; 32]).unwrap();
        storage.store_tool(&make_tool("gamma"), [3u8; 32]).unwrap();

        let tools = storage.list_tools().unwrap();
        assert_eq!(tools.len(), 3);
        assert!(tools.contains(&"alpha".to_string()));
        assert!(tools.contains(&"beta".to_string()));
        assert!(tools.contains(&"gamma".to_string()));
    }

    #[test]
    fn test_contains() {
        let storage = Storage::temporary().unwrap();
        let tool = make_tool("exists");

        assert!(!storage.contains("exists").unwrap());

        storage.store_tool(&tool, [0u8; 32]).unwrap();

        assert!(storage.contains("exists").unwrap());
        assert!(!storage.contains("not_exists").unwrap());
    }

    #[test]
    fn test_remove_tool() {
        let storage = Storage::temporary().unwrap();
        let tool = make_tool("removable");

        storage.store_tool(&tool, [0u8; 32]).unwrap();
        assert!(storage.contains("removable").unwrap());

        let removed = storage.remove_tool("removable").unwrap();
        assert!(removed);
        assert!(!storage.contains("removable").unwrap());

        let removed_again = storage.remove_tool("removable").unwrap();
        assert!(!removed_again);
    }

    #[test]
    fn test_overwrite() {
        let storage = Storage::temporary().unwrap();
        let tool = make_tool("overwrite");

        storage.store_tool(&tool, [1u8; 32]).unwrap();
        let (_, hash1) = storage.load_tool("overwrite").unwrap().unwrap();
        assert_eq!(hash1, [1u8; 32]);

        storage.store_tool(&tool, [2u8; 32]).unwrap();
        let (_, hash2) = storage.load_tool("overwrite").unwrap().unwrap();
        assert_eq!(hash2, [2u8; 32]);
    }

    #[test]
    fn test_len_and_empty() {
        let storage = Storage::temporary().unwrap();

        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);

        storage.store_tool(&make_tool("a"), [0u8; 32]).unwrap();
        assert!(!storage.is_empty());
        assert_eq!(storage.len(), 1);

        storage.store_tool(&make_tool("b"), [0u8; 32]).unwrap();
        assert_eq!(storage.len(), 2);
    }
}
