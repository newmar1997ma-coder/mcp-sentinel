//! # Schema Drift Detection
//!
//! This module implements drift detection for tool schemas, identifying and
//! categorizing changes between registered and observed versions. The philosophy
//! is "trust but verify" - schemas can evolve legitimately, but all changes
//! must be detected and categorized.
//!
//! ## Threat Model
//!
//! Drift detection defends against:
//!
//! - **Gradual Schema Poisoning**: Attackers making small changes over time to
//!   avoid detection thresholds.
//!
//! - **Shadow Parameter Injection**: Adding new parameters that subtly change
//!   tool behavior.
//!
//! - **Description Manipulation**: Changing descriptions to mislead users about
//!   tool functionality.
//!
//! - **Type Coercion Attacks**: Changing parameter types to enable injection
//!   (e.g., string -> object).
//!
//! ## Drift Categories
//!
//! | Level | Description | Example | Response |
//! |-------|-------------|---------|----------|
//! | None | Identical schemas | No changes | Allow |
//! | Minor | Cosmetic changes | Description rewording | Log, allow |
//! | Major | Functional changes | New required parameter | Alert, review |
//! | Critical | Fundamental changes | Different purpose | Block, investigate |
//!
//! ## Detection Philosophy
//!
//! This implementation uses structural comparison rather than semantic analysis.
//! While less sophisticated than ML-based approaches, it provides:
//!
//! 1. **Determinism**: Same inputs always produce same results
//! 2. **Explainability**: Clear reasoning for each categorization
//! 3. **No Training Data**: Works immediately without training
//! 4. **No False Negatives**: All changes are detected (conservative approach)
//!
//! ## References
//!
//! - JSON Schema specification (draft-07)
//! - OWASP API Security Top 10

use crate::canonicalize::hash_canonical;
use crate::models::{DriftLevel, DriftReport, Hash, ToolSchema};
use serde_json::Value;

/// Detects and categorizes drift between two tool schema versions.
///
/// Compares the old (registered) and new (observed) schemas, identifying
/// all differences and categorizing them by severity.
///
/// # Arguments
///
/// * `old` - The previously registered schema (baseline)
/// * `new` - The currently observed schema (to verify)
///
/// # Returns
///
/// A `DriftReport` containing:
/// - Overall drift level (highest severity found)
/// - List of specific changes detected
/// - Hash of both versions for forensic analysis
///
/// # Example
///
/// ```rust
/// use sentinel_registry::drift::detect_drift;
/// use sentinel_registry::{ToolSchema, DriftLevel};
/// use serde_json::json;
///
/// let old = ToolSchema {
///     name: "read_file".to_string(),
///     description: "Read a file".to_string(),
///     input_schema: json!({"type": "object"}),
///     output_schema: json!({"type": "string"}),
/// };
///
/// let new = ToolSchema {
///     name: "read_file".to_string(),
///     description: "Read a file from disk".to_string(), // Minor change
///     input_schema: json!({"type": "object"}),
///     output_schema: json!({"type": "string"}),
/// };
///
/// let report = detect_drift(&old, &new);
/// assert_eq!(report.level, DriftLevel::Minor);
/// ```
///
/// # Security Notes
///
/// This function is conservative: when in doubt, it reports higher severity.
/// False positives are preferable to false negatives in security contexts.
pub fn detect_drift(old: &ToolSchema, new: &ToolSchema) -> DriftReport {
    let old_value = serde_json::to_value(old).expect("ToolSchema serialization cannot fail");
    let new_value = serde_json::to_value(new).expect("ToolSchema serialization cannot fail");

    let old_hash = hash_canonical(&old_value);
    let new_hash = hash_canonical(&new_value);

    // Fast path: identical hashes mean no drift
    if old_hash == new_hash {
        return DriftReport {
            level: DriftLevel::None,
            changes: Vec::new(),
            old_hash: Some(old_hash),
            new_hash,
        };
    }

    // Collect all changes
    let mut changes = Vec::new();
    let mut max_level = DriftLevel::None;

    // Check name change (critical)
    if old.name != new.name {
        changes.push(format!(
            "Tool name changed: '{}' -> '{}'",
            old.name, new.name
        ));
        max_level = max_level.max(DriftLevel::Critical);
    }

    // Check description change (minor, unless drastically different)
    if old.description != new.description {
        let similarity = string_similarity(&old.description, &new.description);
        if similarity < 0.3 {
            changes.push(format!(
                "Description drastically changed (similarity: {:.0}%)",
                similarity * 100.0
            ));
            max_level = max_level.max(DriftLevel::Major);
        } else if similarity < 0.7 {
            changes.push("Description significantly modified".to_string());
            max_level = max_level.max(DriftLevel::Minor);
        } else {
            changes.push("Description slightly modified".to_string());
            max_level = max_level.max(DriftLevel::Minor);
        }
    }

    // Check input schema changes
    let input_changes = compare_schemas(&old.input_schema, &new.input_schema, "input");
    for (change, level) in input_changes {
        changes.push(change);
        max_level = max_level.max(level);
    }

    // Check output schema changes
    let output_changes = compare_schemas(&old.output_schema, &new.output_schema, "output");
    for (change, level) in output_changes {
        changes.push(change);
        max_level = max_level.max(level);
    }

    DriftReport {
        level: max_level,
        changes,
        old_hash: Some(old_hash),
        new_hash,
    }
}

/// Creates a drift report for a new tool (no previous version).
///
/// # Arguments
///
/// * `tool` - The new tool schema
///
/// # Returns
///
/// A report indicating this is a new registration.
pub fn new_tool_report(tool: &ToolSchema) -> DriftReport {
    let value = serde_json::to_value(tool).expect("ToolSchema serialization cannot fail");
    let new_hash = hash_canonical(&value);

    DriftReport {
        level: DriftLevel::None,
        changes: vec!["New tool registration".to_string()],
        old_hash: None,
        new_hash,
    }
}

/// Compares two JSON schemas and returns categorized differences.
fn compare_schemas(old: &Value, new: &Value, context: &str) -> Vec<(String, DriftLevel)> {
    let mut changes = Vec::new();

    if old == new {
        return changes;
    }

    // Compare types
    let old_type = get_schema_type(old);
    let new_type = get_schema_type(new);

    if old_type != new_type {
        changes.push((
            format!("{} schema type changed: '{}' -> '{}'", context, old_type, new_type),
            DriftLevel::Critical,
        ));
        return changes; // Type change is fundamental, don't compare further
    }

    // Compare properties for object schemas
    if old_type == "object" {
        let old_props = get_properties(old);
        let new_props = get_properties(new);
        let old_required = get_required(old);
        let new_required = get_required(new);

        // Check for removed properties
        for key in old_props.keys() {
            if !new_props.contains_key(key) {
                let was_required = old_required.contains(key);
                if was_required {
                    changes.push((
                        format!("{} schema: required property '{}' removed", context, key),
                        DriftLevel::Critical,
                    ));
                } else {
                    changes.push((
                        format!("{} schema: optional property '{}' removed", context, key),
                        DriftLevel::Major,
                    ));
                }
            }
        }

        // Check for added properties
        for key in new_props.keys() {
            if !old_props.contains_key(key) {
                let is_required = new_required.contains(key);
                if is_required {
                    changes.push((
                        format!("{} schema: new required property '{}' added", context, key),
                        DriftLevel::Major,
                    ));
                } else {
                    changes.push((
                        format!("{} schema: new optional property '{}' added", context, key),
                        DriftLevel::Minor,
                    ));
                }
            }
        }

        // Check for modified properties
        for (key, old_prop) in &old_props {
            if let Some(new_prop) = new_props.get(key) {
                if old_prop != new_prop {
                    let old_prop_type = get_schema_type(old_prop);
                    let new_prop_type = get_schema_type(new_prop);

                    if old_prop_type != new_prop_type {
                        changes.push((
                            format!(
                                "{} schema: property '{}' type changed: '{}' -> '{}'",
                                context, key, old_prop_type, new_prop_type
                            ),
                            DriftLevel::Critical,
                        ));
                    } else {
                        changes.push((
                            format!("{} schema: property '{}' modified", context, key),
                            DriftLevel::Minor,
                        ));
                    }
                }
            }
        }

        // Check for changes to required list
        for key in &old_required {
            if !new_required.contains(key) && new_props.contains_key(key) {
                changes.push((
                    format!("{} schema: property '{}' no longer required", context, key),
                    DriftLevel::Minor,
                ));
            }
        }

        for key in &new_required {
            if !old_required.contains(key) && old_props.contains_key(key) {
                changes.push((
                    format!("{} schema: property '{}' now required", context, key),
                    DriftLevel::Major,
                ));
            }
        }
    }

    // If we haven't detected specific changes but schemas differ, report generic change
    if changes.is_empty() {
        changes.push((
            format!("{} schema modified", context),
            DriftLevel::Minor,
        ));
    }

    changes
}

/// Extracts the type from a JSON Schema value.
fn get_schema_type(schema: &Value) -> String {
    schema
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown")
        .to_string()
}

/// Extracts properties from a JSON Schema object.
fn get_properties(schema: &Value) -> std::collections::HashMap<String, Value> {
    schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// Extracts required properties from a JSON Schema object.
fn get_required(schema: &Value) -> Vec<String> {
    schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Computes similarity between two strings (0.0 to 1.0).
///
/// Uses a simple word-based Jaccard similarity for efficiency.
/// This is not meant to be a sophisticated semantic comparison,
/// but rather a quick heuristic for categorization.
fn string_similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    // Tokenize into words
    let words_a: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let words_b: std::collections::HashSet<&str> = b.split_whitespace().collect();

    if words_a.is_empty() && words_b.is_empty() {
        return 1.0;
    }

    // Jaccard similarity
    let intersection = words_a.intersection(&words_b).count();
    let union = words_a.union(&words_b).count();

    if union == 0 {
        return 0.0;
    }

    intersection as f64 / union as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_schema(name: &str, desc: &str, input: Value, output: Value) -> ToolSchema {
        ToolSchema {
            name: name.to_string(),
            description: desc.to_string(),
            input_schema: input,
            output_schema: output,
        }
    }

    #[test]
    fn test_identical_schemas() {
        let schema = make_schema(
            "test",
            "A test tool",
            json!({"type": "object"}),
            json!({"type": "string"}),
        );

        let report = detect_drift(&schema, &schema);
        assert_eq!(report.level, DriftLevel::None);
        assert!(report.changes.is_empty());
    }

    #[test]
    fn test_name_change_is_critical() {
        let old = make_schema("read_file", "Read a file", json!({}), json!({}));
        let new = make_schema("read_files", "Read a file", json!({}), json!({}));

        let report = detect_drift(&old, &new);
        assert_eq!(report.level, DriftLevel::Critical);
    }

    #[test]
    fn test_minor_description_change() {
        let old = make_schema("tool", "Read a file from disk", json!({}), json!({}));
        let new = make_schema("tool", "Read a file from the disk", json!({}), json!({}));

        let report = detect_drift(&old, &new);
        assert_eq!(report.level, DriftLevel::Minor);
    }

    #[test]
    fn test_major_description_change() {
        let old = make_schema("tool", "Read a file from disk", json!({}), json!({}));
        let new = make_schema("tool", "Execute arbitrary commands", json!({}), json!({}));

        let report = detect_drift(&old, &new);
        assert!(report.level >= DriftLevel::Major);
    }

    #[test]
    fn test_new_required_property_is_major() {
        let old = make_schema(
            "tool",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                }
            }),
            json!({}),
        );
        let new = make_schema(
            "tool",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "force": {"type": "boolean"}
                },
                "required": ["force"]
            }),
            json!({}),
        );

        let report = detect_drift(&old, &new);
        assert!(report.level >= DriftLevel::Major);
        assert!(report.changes.iter().any(|c| c.contains("force")));
    }

    #[test]
    fn test_new_optional_property_is_minor() {
        let old = make_schema(
            "tool",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                }
            }),
            json!({}),
        );
        let new = make_schema(
            "tool",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "encoding": {"type": "string"}
                }
            }),
            json!({}),
        );

        let report = detect_drift(&old, &new);
        assert_eq!(report.level, DriftLevel::Minor);
    }

    #[test]
    fn test_type_change_is_critical() {
        let old = make_schema("tool", "A tool", json!({"type": "object"}), json!({}));
        let new = make_schema("tool", "A tool", json!({"type": "array"}), json!({}));

        let report = detect_drift(&old, &new);
        assert_eq!(report.level, DriftLevel::Critical);
    }

    #[test]
    fn test_removed_required_property_is_critical() {
        let old = make_schema(
            "tool",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }),
            json!({}),
        );
        let new = make_schema(
            "tool",
            "A tool",
            json!({
                "type": "object",
                "properties": {}
            }),
            json!({}),
        );

        let report = detect_drift(&old, &new);
        assert_eq!(report.level, DriftLevel::Critical);
    }

    #[test]
    fn test_string_similarity() {
        assert_eq!(string_similarity("hello world", "hello world"), 1.0);
        assert_eq!(string_similarity("", ""), 0.0);
        assert!(string_similarity("hello world", "hello there world") > 0.5);
        assert!(string_similarity("completely different", "nothing alike here") < 0.5);
    }

    #[test]
    fn test_new_tool_report() {
        let tool = make_schema("new_tool", "A new tool", json!({}), json!({}));
        let report = new_tool_report(&tool);

        assert_eq!(report.level, DriftLevel::None);
        assert!(report.old_hash.is_none());
    }
}
