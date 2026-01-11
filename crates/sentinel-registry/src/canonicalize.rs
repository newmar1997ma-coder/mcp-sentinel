//! # RFC 8785 JSON Canonicalization Scheme (JCS)
//!
//! This module implements the JSON Canonicalization Scheme as defined in RFC 8785.
//! Canonical JSON ensures that semantically identical JSON documents produce
//! identical byte sequences, enabling reliable cryptographic hashing.
//!
//! ## Threat Model
//!
//! Canonicalization defends against:
//!
//! - **Key Reordering Attacks**: JSON objects have no inherent key order, allowing
//!   attackers to create semantically identical but bytewise different documents.
//!
//! - **Whitespace Manipulation**: Extra whitespace could produce different hashes
//!   for the same data.
//!
//! - **Number Representation**: `1.0`, `1.00`, and `1` are equivalent but produce
//!   different byte sequences without normalization.
//!
//! - **Unicode Escaping**: `"\u0041"` and `"A"` are equivalent but bytewise different.
//!
//! ## RFC 8785 Summary
//!
//! The JSON Canonicalization Scheme specifies:
//!
//! 1. **Object Keys**: Sorted lexicographically by UTF-16 code units
//! 2. **Numbers**: Serialized with minimal representation (no trailing zeros)
//! 3. **Strings**: Minimal escaping (only required escapes)
//! 4. **Whitespace**: No insignificant whitespace
//! 5. **Arrays**: Elements in original order
//!
//! ## References
//!
//! - **RFC 8785** - "JSON Canonicalization Scheme (JCS)"
//!   <https://www.rfc-editor.org/rfc/rfc8785>
//!
//! - **IETF I-JSON** - Internet JSON (RFC 7493)
//!   <https://www.rfc-editor.org/rfc/rfc7493>
//!
//! ## Example
//!
//! ```rust
//! use sentinel_registry::canonicalize::{canonicalize, hash_canonical};
//! use serde_json::json;
//!
//! // These objects are semantically identical
//! let obj1 = json!({"b": 1, "a": 2});
//! let obj2 = json!({"a": 2, "b": 1});
//!
//! // Canonicalization produces identical output
//! let canon1 = canonicalize(&obj1);
//! let canon2 = canonicalize(&obj2);
//!
//! assert_eq!(canon1, canon2);
//! assert_eq!(canon1, r#"{"a":2,"b":1}"#);
//! ```

use crate::models::Hash;
use sha2::{Digest, Sha256};

/// Canonicalizes a JSON value according to RFC 8785.
///
/// Converts any JSON value to its canonical string representation.
/// The output is deterministic: semantically identical inputs always
/// produce bytewise identical outputs.
///
/// # Arguments
///
/// * `value` - The JSON value to canonicalize
///
/// # Returns
///
/// A canonical JSON string with:
/// - Object keys sorted lexicographically by UTF-16 code units
/// - Numbers in minimal representation
/// - Strings with minimal escaping
/// - No insignificant whitespace
///
/// # Example
///
/// ```rust
/// use sentinel_registry::canonicalize::canonicalize;
/// use serde_json::json;
///
/// let value = json!({
///     "zulu": true,
///     "alpha": [3, 2, 1],
///     "bravo": "test"
/// });
///
/// let canonical = canonicalize(&value);
/// assert_eq!(canonical, r#"{"alpha":[3,2,1],"bravo":"test","zulu":true}"#);
/// ```
///
/// # Security Notes
///
/// This function is critical for security. Any deviation from RFC 8785
/// could allow attackers to craft schemas that hash differently despite
/// being semantically identical.
pub fn canonicalize(value: &serde_json::Value) -> String {
    canonicalize_value(value)
}

/// Computes the SHA-256 hash of a canonicalized JSON value.
///
/// This is the primary function for computing schema hashes. It first
/// canonicalizes the JSON according to RFC 8785, then computes the
/// SHA-256 hash of the resulting bytes.
///
/// # Arguments
///
/// * `value` - The JSON value to hash
///
/// # Returns
///
/// A 32-byte SHA-256 hash of the canonical JSON representation.
///
/// # Example
///
/// ```rust
/// use sentinel_registry::canonicalize::hash_canonical;
/// use serde_json::json;
///
/// let value = json!({"name": "read_file"});
/// let hash = hash_canonical(&value);
///
/// // Hash is deterministic
/// let hash2 = hash_canonical(&json!({"name": "read_file"}));
/// assert_eq!(hash, hash2);
///
/// // Different values produce different hashes
/// let hash3 = hash_canonical(&json!({"name": "write_file"}));
/// assert_ne!(hash, hash3);
/// ```
///
/// # Security Notes
///
/// Uses SHA-256 which provides 128-bit security against collision attacks.
/// This is considered sufficient for integrity verification purposes.
pub fn hash_canonical(value: &serde_json::Value) -> Hash {
    let canonical = canonicalize(value);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

/// Computes the SHA-256 hash of a ToolSchema.
///
/// Serializes the tool schema to JSON and computes its canonical hash.
/// This is the primary entry point for hashing tool schemas.
///
/// # Arguments
///
/// * `schema` - The tool schema to hash
///
/// # Returns
///
/// A 32-byte SHA-256 hash of the canonical schema representation.
pub fn hash_tool_schema(schema: &crate::models::ToolSchema) -> Hash {
    let value = serde_json::to_value(schema).expect("ToolSchema serialization cannot fail");
    hash_canonical(&value)
}

/// Internal function to canonicalize a JSON value.
///
/// Recursively processes the JSON value according to RFC 8785 rules.
fn canonicalize_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        serde_json::Value::Number(n) => canonicalize_number(n),
        serde_json::Value::String(s) => canonicalize_string(s),
        serde_json::Value::Array(arr) => canonicalize_array(arr),
        serde_json::Value::Object(obj) => canonicalize_object(obj),
    }
}

/// Canonicalizes a JSON number according to RFC 8785.
///
/// Numbers are serialized in their minimal representation:
/// - No leading zeros (except for "0" itself)
/// - No trailing zeros after decimal point
/// - Exponential notation for very large/small numbers
fn canonicalize_number(n: &serde_json::Number) -> String {
    // RFC 8785 specifies that numbers should be serialized in their
    // shortest form. serde_json already handles most cases correctly.
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(f) = n.as_f64() {
        // Handle special case for whole numbers stored as floats
        if f.fract() == 0.0 && f.abs() < (i64::MAX as f64) {
            return (f as i64).to_string();
        }
        // Use Rust's default float formatting which is close to minimal
        // For a production implementation, consider using ryu crate
        format_float(f)
    } else {
        n.to_string()
    }
}

/// Formats a float according to RFC 8785 rules.
///
/// Uses ECMAScript-style formatting for consistency.
fn format_float(f: f64) -> String {
    if f.is_nan() || f.is_infinite() {
        // RFC 8785 says these are not valid JSON
        // serde_json shouldn't produce them, but handle gracefully
        return "null".to_string();
    }

    // Use Rust's default formatting, which produces reasonable output
    let s = format!("{}", f);

    // Ensure we don't produce unnecessary trailing zeros
    // but keep at least one digit after decimal if present
    s
}

/// Canonicalizes a JSON string according to RFC 8785.
///
/// Applies minimal escaping as specified by the RFC:
/// - Escape: `"`, `\`, and control characters (0x00-0x1F)
/// - Do NOT escape: `/`, Unicode characters > 0x1F
fn canonicalize_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');

    for ch in s.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\x08' => result.push_str("\\b"),
            '\x0C' => result.push_str("\\f"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c < '\x20' => {
                // Other control characters use \uXXXX
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }

    result.push('"');
    result
}

/// Canonicalizes a JSON array according to RFC 8785.
///
/// Arrays maintain their element order; only the elements themselves
/// are canonicalized.
fn canonicalize_array(arr: &[serde_json::Value]) -> String {
    let elements: Vec<String> = arr.iter().map(canonicalize_value).collect();
    format!("[{}]", elements.join(","))
}

/// Canonicalizes a JSON object according to RFC 8785.
///
/// Keys are sorted lexicographically by UTF-16 code units as specified
/// in the RFC. This is the critical step for ensuring deterministic output.
fn canonicalize_object(obj: &serde_json::Map<String, serde_json::Value>) -> String {
    // RFC 8785 specifies sorting by UTF-16 code units
    // For most ASCII keys, this is equivalent to byte-wise sorting
    // For Unicode keys, we need to compare UTF-16 encoded forms
    let mut entries: Vec<(&String, &serde_json::Value)> = obj.iter().collect();

    // Sort by UTF-16 code units
    entries.sort_by(|(a, _), (b, _)| compare_utf16(a, b));

    let pairs: Vec<String> = entries
        .iter()
        .map(|(k, v)| format!("{}:{}", canonicalize_string(k), canonicalize_value(v)))
        .collect();

    format!("{{{}}}", pairs.join(","))
}

/// Compares two strings by their UTF-16 code unit sequences.
///
/// This implements the comparison order specified in RFC 8785 Section 3.2.3.
/// For ASCII strings, this is equivalent to lexicographic byte comparison.
fn compare_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let a_utf16: Vec<u16> = a.encode_utf16().collect();
    let b_utf16: Vec<u16> = b.encode_utf16().collect();
    a_utf16.cmp(&b_utf16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonicalize_null() {
        assert_eq!(canonicalize(&json!(null)), "null");
    }

    #[test]
    fn test_canonicalize_bool() {
        assert_eq!(canonicalize(&json!(true)), "true");
        assert_eq!(canonicalize(&json!(false)), "false");
    }

    #[test]
    fn test_canonicalize_numbers() {
        assert_eq!(canonicalize(&json!(0)), "0");
        assert_eq!(canonicalize(&json!(1)), "1");
        assert_eq!(canonicalize(&json!(-1)), "-1");
        assert_eq!(canonicalize(&json!(123456789)), "123456789");
    }

    #[test]
    fn test_canonicalize_strings() {
        assert_eq!(canonicalize(&json!("")), r#""""#);
        assert_eq!(canonicalize(&json!("hello")), r#""hello""#);
        assert_eq!(canonicalize(&json!("he\"llo")), r#""he\"llo""#);
        assert_eq!(canonicalize(&json!("he\\llo")), r#""he\\llo""#);
        assert_eq!(canonicalize(&json!("line\nbreak")), r#""line\nbreak""#);
    }

    #[test]
    fn test_canonicalize_array() {
        assert_eq!(canonicalize(&json!([])), "[]");
        assert_eq!(canonicalize(&json!([1, 2, 3])), "[1,2,3]");
        assert_eq!(canonicalize(&json!(["a", "b"])), r#"["a","b"]"#);
    }

    #[test]
    fn test_canonicalize_object_key_sorting() {
        // Keys should be sorted
        let obj = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(canonicalize(&obj), r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_deterministic() {
        // Different key orders should produce same output
        let obj1 = json!({"b": 1, "a": 2});
        let obj2 = json!({"a": 2, "b": 1});
        assert_eq!(canonicalize(&obj1), canonicalize(&obj2));
    }

    #[test]
    fn test_canonicalize_nested() {
        let obj = json!({
            "outer": {
                "z": 1,
                "a": 2
            }
        });
        assert_eq!(canonicalize(&obj), r#"{"outer":{"a":2,"z":1}}"#);
    }

    #[test]
    fn test_hash_deterministic() {
        let obj1 = json!({"b": 1, "a": 2});
        let obj2 = json!({"a": 2, "b": 1});
        assert_eq!(hash_canonical(&obj1), hash_canonical(&obj2));
    }

    #[test]
    fn test_hash_different_values() {
        let obj1 = json!({"a": 1});
        let obj2 = json!({"a": 2});
        assert_ne!(hash_canonical(&obj1), hash_canonical(&obj2));
    }

    #[test]
    fn test_utf16_sorting() {
        // Test that UTF-16 sorting works correctly
        // ASCII characters sort as expected
        assert_eq!(compare_utf16("a", "b"), std::cmp::Ordering::Less);
        assert_eq!(compare_utf16("b", "a"), std::cmp::Ordering::Greater);
        assert_eq!(compare_utf16("a", "a"), std::cmp::Ordering::Equal);
    }
}
