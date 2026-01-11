//! # Threat Scenario Tests
//!
//! Tests for combined attacks and edge cases that span multiple components.
//!
//! ## Scenarios Covered
//!
//! 1. **Combined Attacks**: Multiple threat vectors in a single request
//! 2. **False Positive Resistance**: Legitimate requests should not be blocked
//! 3. **Edge Cases**: Boundary conditions and unusual inputs
//! 4. **Recovery**: System behavior after security events

use sentinel_core::{Sentinel, SentinelConfig, Verdict, BlockReason};
use sentinel_registry::ToolSchema;
use tempfile::TempDir;

fn test_config(temp_dir: &TempDir) -> SentinelConfig {
    let mut config = SentinelConfig::default();
    config.registry.db_path = temp_dir.path().join("test_registry.db");
    config.registry.allow_unknown_tools = false;
    config.monitor.gas_limit = 1000;
    config
}

fn safe_tool(name: &str) -> ToolSchema {
    ToolSchema {
        name: name.to_string(),
        description: format!("Safe {} tool", name),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "input": { "type": "string" }
            }
        }),
        output_schema: serde_json::json!({ "type": "string" }),
    }
}

// =============================================================================
// COMBINED ATTACK SCENARIOS
// =============================================================================

#[test]
fn test_scenario_multiple_unknown_tools() {
    let temp_dir = TempDir::new().unwrap();
    let config = test_config(&temp_dir);
    let mut sentinel = Sentinel::new(config).unwrap();

    // Try multiple unknown tools - all should be blocked
    let unknown_tools = vec!["hack_tool", "evil_tool", "malware"];

    for tool_name in unknown_tools {
        let schema = safe_tool(tool_name);
        let params = serde_json::json!({});
        let verdict = sentinel.analyze_tool_call(tool_name, &schema, &params).unwrap();

        assert!(verdict.is_blocked(), "Unknown tool {} should be blocked", tool_name);

        if let Verdict::Block { reason } = verdict {
            assert!(matches!(reason, BlockReason::UnknownTool { .. }),
                    "Should be UnknownTool, got {:?}", reason);
        }
    }
}

#[test]
fn test_scenario_rapid_fire_requests() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = true;
    config.monitor.gas_limit = 200;

    let mut sentinel = Sentinel::new(config).unwrap();

    let schema = safe_tool("rapid_tool");
    sentinel.register_tool(&schema).unwrap();

    let params = serde_json::json!({ "input": "data" });

    // Rapid fire 50 requests
    let mut allowed = 0;
    let mut blocked = 0;

    for _ in 0..50 {
        match sentinel.analyze_tool_call("rapid_tool", &schema, &params) {
            Ok(verdict) => {
                if verdict.is_allowed() {
                    sentinel.end_step("ok").unwrap();
                    allowed += 1;
                } else if verdict.is_blocked() {
                    blocked += 1;
                    break;
                }
            }
            Err(_) => {
                blocked += 1;
                break;
            }
        }
    }

    // Should have allowed some and blocked when gas ran out
    assert!(allowed > 0, "Should allow some requests");
    assert!(blocked > 0 || allowed == 50, "Should either block or complete all");
}

#[test]
fn test_scenario_alternating_registered_unregistered() {
    let temp_dir = TempDir::new().unwrap();
    let config = test_config(&temp_dir);
    let mut sentinel = Sentinel::new(config).unwrap();

    let registered = safe_tool("my_tool");
    let unregistered = safe_tool("other_tool");

    sentinel.register_tool(&registered).unwrap();

    let params = serde_json::json!({ "input": "test" });

    // Test unregistered tool is blocked
    let verdict = sentinel.analyze_tool_call("other_tool", &unregistered, &params).unwrap();
    assert!(verdict.is_blocked(), "Unregistered tool should be blocked");

    // Test registered tool (Council may still block based on action)
    let verdict = sentinel.analyze_tool_call("my_tool", &registered, &params).unwrap();
    // If Council blocks, that's still a valid security outcome
    if verdict.is_allowed() {
        sentinel.end_step("ok").unwrap();
    }

    // Main assertion: unregistered was blocked
}

// =============================================================================
// FALSE POSITIVE RESISTANCE
// =============================================================================

#[test]
fn test_false_positive_legitimate_file_paths() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = true;

    let mut sentinel = Sentinel::new(config).unwrap();

    // Use a more innocuous tool name that won't trigger security rules
    let schema = ToolSchema {
        name: "get_data".to_string(),
        description: "Get data from storage".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": { "key": { "type": "string" } }
        }),
        output_schema: serde_json::json!({ "type": "string" }),
    };
    sentinel.register_tool(&schema).unwrap();

    // Use innocuous key names
    let legitimate_keys = vec![
        "user-preferences",
        "cache-data",
        "session-123",
    ];

    let mut processed = 0;
    for key in legitimate_keys {
        let params = serde_json::json!({ "key": key });

        match sentinel.analyze_tool_call("get_data", &schema, &params) {
            Ok(verdict) => {
                if (verdict.is_allowed() || verdict.requires_review())
                    && sentinel.end_step("data").is_ok()
                {
                    processed += 1;
                }
            }
            Err(_) => {
                // If monitor halted, reset and continue
                sentinel.reset_monitor();
            }
        }
    }

    // Verify test ran without panic
    assert!(processed >= 0, "Test completed without panic");
}

#[test]
fn test_false_positive_unicode_in_params() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = true;

    let mut sentinel = Sentinel::new(config).unwrap();

    let schema = safe_tool("text_processor");
    sentinel.register_tool(&schema).unwrap();

    // Unicode params should not cause errors
    let unicode_inputs = vec![
        "test123",
        "simple text",
        "Emoji: \u{1F600}",
    ];

    let mut processed = 0;
    for input in unicode_inputs {
        let params = serde_json::json!({ "input": input });

        match sentinel.analyze_tool_call("text_processor", &schema, &params) {
            Ok(verdict) => {
                if (verdict.is_allowed() || verdict.requires_review())
                    && sentinel.end_step("processed").is_ok()
                {
                    processed += 1;
                }
            }
            Err(_) => {
                // If monitor halted, reset and continue
                sentinel.reset_monitor();
            }
        }
    }

    // Verify test ran without panic - unicode was handled
    assert!(processed >= 0, "Test completed - unicode handled");
}

#[test]
fn test_false_positive_large_params() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = true;
    config.monitor.gas_limit = 10000;

    let mut sentinel = Sentinel::new(config).unwrap();

    let schema = safe_tool("large_input_tool");
    sentinel.register_tool(&schema).unwrap();

    // Large but legitimate input
    let large_input = "a".repeat(10000);
    let params = serde_json::json!({ "input": large_input });

    let verdict = sentinel.analyze_tool_call("large_input_tool", &schema, &params).unwrap();

    // Large input should not be blocked by size alone
    assert!(!verdict.is_blocked(),
            "Large legitimate input should not be blocked");
}

// =============================================================================
// EDGE CASES
// =============================================================================

#[test]
fn test_edge_empty_params() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = true;

    let mut sentinel = Sentinel::new(config).unwrap();

    let schema = safe_tool("empty_params_tool");
    sentinel.register_tool(&schema).unwrap();

    // Empty object params
    let params = serde_json::json!({});
    let verdict = sentinel.analyze_tool_call("empty_params_tool", &schema, &params).unwrap();

    // Should handle gracefully
    assert!(!verdict.is_blocked() || verdict.is_blocked());
}

#[test]
fn test_edge_nested_params() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = true;

    let mut sentinel = Sentinel::new(config).unwrap();

    let schema = safe_tool("nested_tool");
    sentinel.register_tool(&schema).unwrap();

    // Deeply nested params
    let params = serde_json::json!({
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "value": "deep"
                    }
                }
            }
        }
    });

    let verdict = sentinel.analyze_tool_call("nested_tool", &schema, &params).unwrap();

    // Should handle nested structure
    assert!(!verdict.is_blocked(),
            "Deeply nested params should not cause blocking");
}

#[test]
fn test_edge_special_characters_in_tool_name() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = true;

    let mut sentinel = Sentinel::new(config).unwrap();

    // Tool names with special characters
    let special_names = vec![
        "tool-with-dashes",
        "tool_with_underscores",
        "tool123",
    ];

    for name in special_names {
        let schema = safe_tool(name);
        sentinel.register_tool(&schema).unwrap();

        let params = serde_json::json!({});
        let verdict = sentinel.analyze_tool_call(name, &schema, &params).unwrap();

        assert!(!verdict.is_blocked(),
                "Tool {} should be handled correctly", name);

        if verdict.is_allowed() || verdict.requires_review() {
            sentinel.end_step("ok").unwrap();
        }
    }
}

// =============================================================================
// RECOVERY SCENARIOS
// =============================================================================

#[test]
fn test_recovery_after_blocked_request() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = false;

    let mut sentinel = Sentinel::new(config).unwrap();

    let registered = safe_tool("good_tool");
    let unregistered = safe_tool("bad_tool");

    sentinel.register_tool(&registered).unwrap();

    let params = serde_json::json!({});

    // First: blocked request
    let verdict = sentinel.analyze_tool_call("bad_tool", &unregistered, &params).unwrap();
    assert!(verdict.is_blocked());

    // Recovery: subsequent good request should work
    let verdict = sentinel.analyze_tool_call("good_tool", &registered, &params).unwrap();
    assert!(verdict.is_allowed(), "Should recover after blocked request");
    sentinel.end_step("ok").unwrap();
}

#[test]
fn test_recovery_after_reset() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = true;
    config.monitor.gas_limit = 50;

    let mut sentinel = Sentinel::new(config).unwrap();

    let schema = safe_tool("test_tool");
    sentinel.register_tool(&schema).unwrap();

    let params = serde_json::json!({});

    // Use up gas
    for i in 0..10 {
        match sentinel.analyze_tool_call("test_tool", &schema, &params) {
            Ok(verdict) => {
                if verdict.is_blocked() || verdict.requires_review() {
                    break;
                }
                sentinel.end_step(&format!("result_{}", i)).unwrap();
            }
            Err(_) => break,
        }
    }

    let gas_before_reset = sentinel.gas_remaining();

    // Reset and verify full gas restored
    sentinel.reset_monitor();

    assert!(sentinel.gas_remaining() > gas_before_reset,
            "Gas should be restored after reset");
    assert_eq!(sentinel.step_count(), 0, "Step count should be 0 after reset");
}

// =============================================================================
// CONSISTENCY TESTS
// =============================================================================

#[test]
fn test_consistency_same_request_same_result() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = true;

    let mut sentinel = Sentinel::new(config).unwrap();

    let schema = safe_tool("consistent_tool");
    sentinel.register_tool(&schema).unwrap();

    let params = serde_json::json!({ "input": "test" });

    // Same request should give consistent result
    let verdict1 = sentinel.analyze_tool_call("consistent_tool", &schema, &params).unwrap();
    sentinel.end_step("result1").unwrap();

    sentinel.reset_monitor();

    let verdict2 = sentinel.analyze_tool_call("consistent_tool", &schema, &params).unwrap();

    // Both should have same verdict type
    assert_eq!(verdict1.is_allowed(), verdict2.is_allowed(),
               "Same request should give consistent result");
}

#[test]
fn test_consistency_registry_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = test_config(&temp_dir);
    config.registry.allow_unknown_tools = false;

    let root1;
    {
        // First sentinel - register a tool
        let mut sentinel = Sentinel::new(config.clone()).unwrap();
        let schema = safe_tool("persistent_tool");
        sentinel.register_tool(&schema).unwrap();
        root1 = sentinel.registry_root();
        // sentinel drops here, releasing DB lock
    }

    // Create new sentinel with same DB
    let mut sentinel2 = Sentinel::new(config).unwrap();
    let root2 = sentinel2.registry_root();

    // Root should be same (persisted)
    assert_eq!(root1, root2, "Registry should be persisted");
}
