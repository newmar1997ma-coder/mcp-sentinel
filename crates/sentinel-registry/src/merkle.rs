//! # Merkle Tree Implementation
//!
//! This module implements a Merkle tree (hash tree) for efficient verification
//! of tool schema integrity. Merkle trees allow proving membership without
//! revealing the entire dataset, enabling distributed verification scenarios.
//!
//! ## Threat Model
//!
//! The Merkle tree provides:
//!
//! - **Tamper Evidence**: Any modification to a leaf changes the root hash.
//! - **Efficient Proofs**: O(log n) proof size for n items.
//! - **Distributed Trust**: Root hash can be shared independently of data.
//! - **Collision Resistance**: SHA-256 prevents crafted hash collisions.
//!
//! ## How Merkle Trees Work
//!
//! ```text
//!                    Root Hash
//!                   /         \
//!                  /           \
//!           H(H1+H2)           H(H3+H4)
//!            /    \             /    \
//!           /      \           /      \
//!         H1       H2        H3       H4
//!         |        |         |        |
//!       Leaf1    Leaf2     Leaf3    Leaf4
//! ```
//!
//! To prove Leaf2 is in the tree:
//! 1. Provide H1 (sibling) and H(H3+H4) (uncle)
//! 2. Verifier computes: H(H1 + H(Leaf2)) = H1+H2
//! 3. Then: H(H1+H2 + H(H3+H4)) = Root
//! 4. Compare with trusted root
//!
//! ## References
//!
//! - **Merkle, R. C. (1979)** - "Secrecy, Authentication, and Public Key Systems"
//!   Original introduction of hash trees.
//!   <https://www.ralphmerkle.com/papers/Thesis1979.pdf>
//!
//! - **Merkle, R. C. (1987)** - "A Digital Signature Based on a Conventional
//!   Encryption Function" - Practical construction and applications.
//!   CRYPTO '87. <https://doi.org/10.1007/3-540-48184-2_32>
//!
//! - **RFC 6962** - Certificate Transparency (modern Merkle tree usage)
//!   <https://www.rfc-editor.org/rfc/rfc6962>

use crate::models::{Hash, MerkleProof, MerkleProofNode, HASH_SIZE};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// An empty hash (all zeros) used as a placeholder.
pub const EMPTY_HASH: Hash = [0u8; HASH_SIZE];

/// A Merkle tree for tool schema verification.
///
/// This implementation uses a key-value approach where each tool name
/// maps to its schema hash. The tree is rebuilt when entries change,
/// ensuring the root hash always reflects the current state.
///
/// # Structure
///
/// The tree stores leaves indexed by tool name. Internal nodes are
/// computed on-demand when the root hash or proofs are requested.
///
/// # Thread Safety
///
/// This structure is not thread-safe. Use external synchronization
/// if accessed from multiple threads.
///
/// # Example
///
/// ```rust
/// use sentinel_registry::merkle::MerkleTree;
///
/// let mut tree = MerkleTree::new();
///
/// // Insert tool hashes
/// let hash1 = [1u8; 32];
/// let hash2 = [2u8; 32];
///
/// tree.insert("tool_a", hash1);
/// tree.insert("tool_b", hash2);
///
/// // Get the root hash
/// let root = tree.get_root();
///
/// // Generate a proof for tool_a
/// if let Some(proof) = tree.get_proof("tool_a") {
///     // Proof can be verified independently
///     assert!(MerkleTree::verify_proof(&proof, &root));
/// }
/// ```
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Leaf nodes indexed by tool name.
    leaves: BTreeMap<String, Hash>,

    /// Cached root hash (invalidated on modification).
    cached_root: Option<Hash>,
}

impl MerkleTree {
    /// Creates a new empty Merkle tree.
    ///
    /// # Returns
    ///
    /// An empty tree with no leaves. The root hash of an empty tree
    /// is all zeros.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::merkle::MerkleTree;
    ///
    /// let tree = MerkleTree::new();
    /// assert_eq!(tree.len(), 0);
    /// ```
    pub fn new() -> Self {
        MerkleTree {
            leaves: BTreeMap::new(),
            cached_root: None,
        }
    }

    /// Inserts or updates a leaf in the tree.
    ///
    /// The root hash cache is invalidated and will be recomputed
    /// on the next call to `get_root()`.
    ///
    /// # Arguments
    ///
    /// * `key` - The tool name (unique identifier)
    /// * `hash` - The SHA-256 hash of the tool's canonical schema
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::merkle::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// tree.insert("read_file", [1u8; 32]);
    /// tree.insert("write_file", [2u8; 32]);
    ///
    /// assert_eq!(tree.len(), 2);
    /// ```
    pub fn insert(&mut self, key: &str, hash: Hash) {
        self.leaves.insert(key.to_string(), hash);
        self.cached_root = None; // Invalidate cache
    }

    /// Removes a leaf from the tree.
    ///
    /// # Arguments
    ///
    /// * `key` - The tool name to remove
    ///
    /// # Returns
    ///
    /// The removed hash, if the key existed.
    pub fn remove(&mut self, key: &str) -> Option<Hash> {
        let result = self.leaves.remove(key);
        if result.is_some() {
            self.cached_root = None;
        }
        result
    }

    /// Gets the hash for a specific tool.
    ///
    /// # Arguments
    ///
    /// * `key` - The tool name to look up
    ///
    /// # Returns
    ///
    /// The hash if found, None otherwise.
    pub fn get(&self, key: &str) -> Option<&Hash> {
        self.leaves.get(key)
    }

    /// Returns the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Returns true if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Computes and returns the root hash of the tree.
    ///
    /// The root hash is cached and reused until the tree is modified.
    /// For an empty tree, returns all zeros.
    ///
    /// # Returns
    ///
    /// The 32-byte root hash representing the entire tree state.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::merkle::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// let empty_root = tree.get_root();
    ///
    /// tree.insert("tool", [1u8; 32]);
    /// let new_root = tree.get_root();
    ///
    /// // Root changes when leaves change
    /// assert_ne!(empty_root, new_root);
    /// ```
    pub fn get_root(&mut self) -> Hash {
        if let Some(cached) = self.cached_root {
            return cached;
        }

        let root = self.compute_root();
        self.cached_root = Some(root);
        root
    }

    /// Generates a Merkle proof for a specific leaf.
    ///
    /// The proof contains the sibling hashes needed to reconstruct
    /// the path from the leaf to the root.
    ///
    /// # Arguments
    ///
    /// * `key` - The tool name to generate a proof for
    ///
    /// # Returns
    ///
    /// A `MerkleProof` if the key exists, None otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::merkle::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// tree.insert("tool_a", [1u8; 32]);
    /// tree.insert("tool_b", [2u8; 32]);
    ///
    /// if let Some(proof) = tree.get_proof("tool_a") {
    ///     let root = tree.get_root();
    ///     assert!(MerkleTree::verify_proof(&proof, &root));
    /// }
    /// ```
    pub fn get_proof(&mut self, key: &str) -> Option<MerkleProof> {
        let leaf_hash = *self.leaves.get(key)?;
        let root_hash = self.get_root();

        // Get sorted keys for consistent ordering
        let keys: Vec<&String> = self.leaves.keys().collect();
        let index = keys.iter().position(|k| *k == key)?;

        // Build proof path
        let hashes: Vec<Hash> = keys.iter().map(|k| self.leaves[*k]).collect();
        let path = self.build_proof_path(&hashes, index);

        Some(MerkleProof {
            leaf_hash,
            path,
            root_hash,
        })
    }

    /// Verifies a Merkle proof against a trusted root hash.
    ///
    /// This is a static method that can verify proofs without access
    /// to the original tree, enabling distributed verification.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `expected_root` - The trusted root hash to verify against
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise.
    ///
    /// # Security Notes
    ///
    /// The `expected_root` must come from a trusted source. If an
    /// attacker can substitute the root, they can forge proofs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_registry::merkle::MerkleTree;
    ///
    /// let mut tree = MerkleTree::new();
    /// tree.insert("tool", [1u8; 32]);
    ///
    /// let root = tree.get_root();
    /// let proof = tree.get_proof("tool").unwrap();
    ///
    /// // Valid proof
    /// assert!(MerkleTree::verify_proof(&proof, &root));
    ///
    /// // Invalid root fails
    /// let fake_root = [0u8; 32];
    /// assert!(!MerkleTree::verify_proof(&proof, &fake_root));
    /// ```
    pub fn verify_proof(proof: &MerkleProof, expected_root: &Hash) -> bool {
        let mut current = proof.leaf_hash;

        for node in &proof.path {
            current = if node.is_left {
                hash_pair(&node.hash, &current)
            } else {
                hash_pair(&current, &node.hash)
            };
        }

        current == *expected_root
    }

    /// Computes the root hash from all leaves.
    fn compute_root(&self) -> Hash {
        if self.leaves.is_empty() {
            return EMPTY_HASH;
        }

        // Get hashes in sorted key order
        let hashes: Vec<Hash> = self.leaves.values().cloned().collect();
        self.build_tree(&hashes)
    }

    /// Builds the tree and returns the root hash.
    fn build_tree(&self, hashes: &[Hash]) -> Hash {
        if hashes.is_empty() {
            return EMPTY_HASH;
        }
        if hashes.len() == 1 {
            return hashes[0];
        }

        // Build tree level by level
        let mut current_level = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_pair(&chunk[0], &chunk[1]));
                } else {
                    // Odd number of nodes: duplicate the last one
                    next_level.push(hash_pair(&chunk[0], &chunk[0]));
                }
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Builds the proof path for a specific leaf index.
    fn build_proof_path(&self, hashes: &[Hash], leaf_index: usize) -> Vec<MerkleProofNode> {
        if hashes.len() <= 1 {
            return Vec::new();
        }

        let mut path = Vec::new();
        let mut current_level = hashes.to_vec();
        let mut index = leaf_index;

        while current_level.len() > 1 {
            // Find sibling
            let sibling_index = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };

            // Get sibling hash (duplicate last if needed)
            let sibling_hash = if sibling_index < current_level.len() {
                current_level[sibling_index]
            } else {
                current_level[index] // Duplicate for odd count
            };

            path.push(MerkleProofNode {
                hash: sibling_hash,
                is_left: index % 2 == 1, // Sibling is on left if we're on right
            });

            // Build next level
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_pair(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(hash_pair(&chunk[0], &chunk[0]));
                }
            }

            current_level = next_level;
            index /= 2;
        }

        path
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Hashes two child hashes together to form a parent hash.
///
/// This is the fundamental building block of the Merkle tree.
/// The left and right hashes are concatenated and hashed with SHA-256.
///
/// # Arguments
///
/// * `left` - The left child hash
/// * `right` - The right child hash
///
/// # Returns
///
/// The SHA-256 hash of the concatenated children.
fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let mut tree = MerkleTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert_eq!(tree.get_root(), EMPTY_HASH);
    }

    #[test]
    fn test_single_leaf() {
        let mut tree = MerkleTree::new();
        let hash = [1u8; 32];
        tree.insert("tool", hash);

        assert_eq!(tree.len(), 1);
        assert_eq!(tree.get("tool"), Some(&hash));
        // Single leaf: root is the leaf itself
        assert_eq!(tree.get_root(), hash);
    }

    #[test]
    fn test_two_leaves() {
        let mut tree = MerkleTree::new();
        tree.insert("a", [1u8; 32]);
        tree.insert("b", [2u8; 32]);

        let root = tree.get_root();
        assert_ne!(root, EMPTY_HASH);
        assert_ne!(root, [1u8; 32]);
        assert_ne!(root, [2u8; 32]);
    }

    #[test]
    fn test_root_changes_with_insertion() {
        let mut tree = MerkleTree::new();
        tree.insert("a", [1u8; 32]);
        let root1 = tree.get_root();

        tree.insert("b", [2u8; 32]);
        let root2 = tree.get_root();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_root_deterministic() {
        let mut tree1 = MerkleTree::new();
        tree1.insert("a", [1u8; 32]);
        tree1.insert("b", [2u8; 32]);

        let mut tree2 = MerkleTree::new();
        // Insert in different order - BTreeMap sorts by key
        tree2.insert("b", [2u8; 32]);
        tree2.insert("a", [1u8; 32]);

        assert_eq!(tree1.get_root(), tree2.get_root());
    }

    #[test]
    fn test_proof_single_leaf() {
        let mut tree = MerkleTree::new();
        tree.insert("tool", [1u8; 32]);

        let root = tree.get_root();
        let proof = tree.get_proof("tool").unwrap();

        assert!(MerkleTree::verify_proof(&proof, &root));
    }

    #[test]
    fn test_proof_two_leaves() {
        let mut tree = MerkleTree::new();
        tree.insert("a", [1u8; 32]);
        tree.insert("b", [2u8; 32]);

        let root = tree.get_root();

        let proof_a = tree.get_proof("a").unwrap();
        let proof_b = tree.get_proof("b").unwrap();

        assert!(MerkleTree::verify_proof(&proof_a, &root));
        assert!(MerkleTree::verify_proof(&proof_b, &root));
    }

    #[test]
    fn test_proof_multiple_leaves() {
        let mut tree = MerkleTree::new();
        for i in 0..5 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            tree.insert(&format!("tool_{}", i), hash);
        }

        let root = tree.get_root();

        for i in 0..5 {
            let proof = tree.get_proof(&format!("tool_{}", i)).unwrap();
            assert!(MerkleTree::verify_proof(&proof, &root));
        }
    }

    #[test]
    fn test_proof_fails_with_wrong_root() {
        let mut tree = MerkleTree::new();
        tree.insert("tool", [1u8; 32]);

        let proof = tree.get_proof("tool").unwrap();
        let fake_root = [0u8; 32];

        assert!(!MerkleTree::verify_proof(&proof, &fake_root));
    }

    #[test]
    fn test_proof_not_found() {
        let mut tree = MerkleTree::new();
        tree.insert("tool", [1u8; 32]);

        assert!(tree.get_proof("nonexistent").is_none());
    }

    #[test]
    fn test_remove_leaf() {
        let mut tree = MerkleTree::new();
        tree.insert("a", [1u8; 32]);
        tree.insert("b", [2u8; 32]);

        let root_before = tree.get_root();
        tree.remove("b");
        let root_after = tree.get_root();

        assert_ne!(root_before, root_after);
        assert_eq!(tree.len(), 1);
    }
}
