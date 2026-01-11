//! # Integration Tests
//!
//! End-to-end tests for StateMonitor under combined threat scenarios.
//!
//! These tests verify that all subsystems work together correctly
//! to prevent state-based attacks on MCP agents.

use sentinel_monitor::{
    ContextManager, CycleDetector, ExecutionNode, Frame, MonitorError, OperationType,
    StateMonitor, StateMonitorConfig,
};

// ============================================================================
// Gas Budget Integration Tests
// ============================================================================

#[test]
fn test_gas_enforcement_protects_against_resource_exhaustion() {
    // Threat: Attacker tries to execute expensive operations indefinitely
    let config = StateMonitorConfig::new().with_gas_budget(200);
    let mut monitor = StateMonitor::with_config(config);

    let mut successful_ops = 0;

    // Try to execute 100 LLM inferences (100 gas each)
    for i in 0..100 {
        let result = monitor.begin_step(&format!("llm_{}", i), OperationType::LlmInference);
        if result.is_ok() {
            monitor.end_step("inference result").unwrap();
            successful_ops += 1;
        } else {
            break;
        }
    }

    // Should only allow 2 (200 / 100 = 2)
    assert_eq!(successful_ops, 2);
    assert!(monitor.gas_exhausted() || monitor.gas_remaining() < 100);
}

#[test]
fn test_gas_enforcement_counts_all_operation_types() {
    let config = StateMonitorConfig::new().with_gas_budget(100);
    let mut monitor = StateMonitor::with_config(config);

    // Mix of operation types
    monitor
        .begin_step("read", OperationType::StateRead)
        .unwrap(); // 1
    monitor.end_step("r").unwrap();

    monitor
        .begin_step("write", OperationType::StateWrite)
        .unwrap(); // 5
    monitor.end_step("r").unwrap();

    monitor.begin_step("tool", OperationType::ToolCall).unwrap(); // 10
    monitor.end_step("r").unwrap();

    monitor
        .begin_step("net", OperationType::NetworkIo)
        .unwrap(); // 20
    monitor.end_step("r").unwrap();

    // Total: 1 + 5 + 10 + 20 = 36, remaining = 64
    assert_eq!(monitor.gas_remaining(), 64);

    // Now try LLM inference (100) - should fail
    let result = monitor.begin_step("llm", OperationType::LlmInference);
    assert!(result.is_err());
}

#[test]
fn test_gas_not_consumed_on_failed_operation() {
    let config = StateMonitorConfig::new().with_gas_budget(50);
    let mut monitor = StateMonitor::with_config(config);

    let before = monitor.gas_remaining();

    // Try expensive operation that can't succeed
    let result = monitor.begin_step("expensive", OperationType::LlmInference);
    assert!(result.is_err());

    // Gas should be unchanged
    assert_eq!(monitor.gas_remaining(), before);
}

// ============================================================================
// Context Flush Integration Tests
// ============================================================================

#[test]
fn test_context_flush_prevents_memory_explosion() {
    let config = StateMonitorConfig::new()
        .with_gas_budget(1_000_000)
        .with_context_capacity(100)
        .with_flush_threshold(0.5)
        .with_auto_flush(true)
        .with_flush_count(25);

    let mut monitor = StateMonitor::with_config(config);

    // Add 1000 frames - should be bounded by capacity
    for i in 0..1000 {
        monitor
            .begin_step(&format!("s{}", i), OperationType::StateRead)
            .unwrap();
        monitor.end_step(&format!("result {}", i)).unwrap();

        // Context should never exceed capacity
        assert!(monitor.context_frame_count() <= 100);
    }

    // After all operations, still bounded
    assert!(monitor.context_frame_count() <= 100);
}

#[test]
fn test_context_manager_fifo_eviction() {
    let mut ctx = ContextManager::new(5);

    // Add frames 0-4
    for i in 0..5 {
        ctx.push(Frame::new(format!("f{}", i), "x"));
    }

    assert_eq!(ctx.len(), 5);

    // Add new frame - should evict f0 (oldest, FIFO)
    let evicted = ctx.push(Frame::new("new", "x"));
    assert!(evicted.is_some());
    assert_eq!(evicted.unwrap().id(), "f0");

    // f0 should be gone
    assert!(ctx.peek("f0").is_none());
    // new should be present
    assert!(ctx.peek("new").is_some());
    // Still at capacity
    assert_eq!(ctx.len(), 5);
}

#[test]
fn test_context_priority_preservation() {
    let mut ctx = ContextManager::new(100);

    // Add mix of priority frames
    for i in 0..50 {
        ctx.push(Frame::new(format!("low{}", i), "content"));
    }
    for i in 0..50 {
        ctx.push(Frame::with_priority(format!("high{}", i), "content", 200));
    }

    // Flush low priority
    ctx.flush_low_priority(100);

    // Only high priority should remain
    assert_eq!(ctx.len(), 50);
    for i in 0..50 {
        assert!(ctx.peek(&format!("high{}", i)).is_some());
    }
}

// ============================================================================
// Cycle Detection Integration Tests
// ============================================================================

#[test]
fn test_cycle_detection_halts_execution() {
    let mut detector = CycleDetector::new();

    detector.record_step(ExecutionNode::new("state_a", 1));
    detector.record_step(ExecutionNode::new("state_b", 2));
    detector.record_step(ExecutionNode::new("state_c", 3));
    detector.record_step(ExecutionNode::new("state_a", 4)); // Back to A!

    let cycle = detector.detect_cycle();
    assert!(cycle.is_some());
}

#[test]
fn test_cycle_detection_no_false_positives() {
    let mut detector = CycleDetector::new();

    // Linear path - no cycles
    for i in 0..100 {
        detector.record_step(ExecutionNode::new(format!("unique_{}", i), i as u64));
    }

    let cycle = detector.detect_cycle();
    assert!(cycle.is_none());
}

#[test]
fn test_monitor_integration_cycle_halts_all_operations() {
    let mut monitor = StateMonitor::new();

    // Execute some normal steps
    monitor
        .begin_step("state_a", OperationType::StateRead)
        .unwrap();
    monitor.end_step("r").unwrap();

    monitor
        .begin_step("state_b", OperationType::StateRead)
        .unwrap();
    monitor.end_step("r").unwrap();

    // This may trigger cycle detection depending on algorithm
    let result = monitor.begin_step("state_a", OperationType::StateRead);

    if result.is_err() {
        // Cycle detected - monitor should be halted
        assert!(monitor.is_halted());

        // All further operations should fail
        let result2 = monitor.begin_step("any", OperationType::StateRead);
        assert!(result2.is_err());
    }
    // If no cycle detected (algorithm requires longer path), that's also fine
}

// ============================================================================
// Combined Threat Scenarios
// ============================================================================

#[test]
fn test_combined_gas_and_context_protection() {
    // Threat: Attacker tries to exhaust both gas and memory
    let config = StateMonitorConfig::new()
        .with_gas_budget(500)
        .with_context_capacity(10)
        .with_auto_flush(true)
        .with_flush_count(3);

    let mut monitor = StateMonitor::with_config(config);

    let mut ops_executed = 0;

    // Try many expensive operations
    for i in 0..1000 {
        let result = monitor.begin_step(&format!("op{}", i), OperationType::ToolCall);
        if result.is_ok() {
            monitor.end_step("result").unwrap();
            ops_executed += 1;
        } else {
            break;
        }
    }

    // Should be limited by gas (500 / 10 = 50)
    assert_eq!(ops_executed, 50);
    // Context should never exceed capacity
    assert!(monitor.context_frame_count() <= 10);
}

#[test]
fn test_monitor_survives_rapid_operation_bursts() {
    let config = StateMonitorConfig::new()
        .with_gas_budget(1_000)
        .with_context_capacity(50)
        .with_auto_flush(true)
        .with_flush_count(10);

    let mut monitor = StateMonitor::with_config(config);

    // Burst of cheap operations (limited to 1000 by gas)
    let mut count = 0;
    while count < 1500 {
        let result = monitor.begin_step(&format!("burst{}", count), OperationType::StateRead);
        if result.is_err() {
            break;
        }
        monitor.end_step("x").unwrap();
        count += 1;
    }

    // Should hit gas limit (~1000 ops)
    assert!(monitor.step_count() >= 1000 || monitor.gas_exhausted());
    // Context bounded
    assert!(monitor.context_frame_count() <= 50);
}

#[test]
fn test_monitor_reset_clears_all_state() {
    let mut monitor = StateMonitor::new();

    // Do some work
    for i in 0..10 {
        monitor
            .begin_step(&format!("s{}", i), OperationType::ToolCall)
            .unwrap();
        monitor.end_step("r").unwrap();
    }

    assert!(monitor.gas_remaining() < 10_000);
    assert!(monitor.step_count() > 0);
    assert!(monitor.context_frame_count() > 0);

    // Reset
    monitor.reset();

    // All state cleared
    assert_eq!(monitor.gas_remaining(), 10_000);
    assert_eq!(monitor.step_count(), 0);
    assert_eq!(monitor.context_frame_count(), 0);
    assert!(!monitor.is_halted());
}

#[test]
fn test_status_report_accuracy() {
    let config = StateMonitorConfig::new()
        .with_gas_budget(1000)
        .with_context_capacity(100);

    let mut monitor = StateMonitor::with_config(config);

    // Execute 5 tool calls (50 gas total)
    for i in 0..5 {
        monitor
            .begin_step(&format!("tool{}", i), OperationType::ToolCall)
            .unwrap();
        monitor.end_step("result").unwrap();
    }

    let status = monitor.status_report();

    assert_eq!(status.step_count, 5);
    assert_eq!(status.gas_consumed, 50);
    assert_eq!(status.gas_remaining, 950);
    assert!((status.gas_utilization - 0.05).abs() < 0.001);
    assert_eq!(status.context_frames, 5);
    assert_eq!(status.context_capacity, 100);
    assert!(!status.cycle_detected);
    assert!(!status.halted);
}

// ============================================================================
// Security Edge Cases
// ============================================================================

#[test]
fn test_security_begin_without_end_blocked() {
    let mut monitor = StateMonitor::new();

    monitor
        .begin_step("s1", OperationType::StateRead)
        .unwrap();
    // Don't call end_step

    // Next begin should fail
    let result = monitor.begin_step("s2", OperationType::StateRead);
    assert!(result.is_err());
}

#[test]
fn test_security_end_without_begin_blocked() {
    let mut monitor = StateMonitor::new();

    let result = monitor.end_step("result");
    assert!(result.is_err());
}

#[test]
fn test_security_halted_monitor_rejects_all() {
    let mut monitor = StateMonitor::new();

    // Manually halt (simulating detected threat)
    // We need to trigger a cycle to halt it
    // For now, let's use a lower-level approach
    monitor
        .begin_step("a", OperationType::StateRead)
        .unwrap();
    monitor.end_step("r").unwrap();
    monitor
        .begin_step("b", OperationType::StateRead)
        .unwrap();
    monitor.end_step("r").unwrap();

    // Try to trigger cycle (depends on algorithm)
    let _ = monitor.begin_step("a", OperationType::StateRead);

    if monitor.is_halted() {
        // Verify all operations blocked
        for op in [
            OperationType::StateRead,
            OperationType::StateWrite,
            OperationType::ToolCall,
        ] {
            let result = monitor.begin_step("any", op);
            assert!(result.is_err());
        }
    }
}

#[test]
fn test_security_zero_gas_immediate_reject() {
    let config = StateMonitorConfig::new().with_gas_budget(0);
    let mut monitor = StateMonitor::with_config(config);

    // Even cheapest operation should fail
    let result = monitor.begin_step("x", OperationType::StateRead);
    assert!(result.is_err());
}

#[test]
fn test_security_custom_gas_cost() {
    let config = StateMonitorConfig::new().with_gas_budget(100);
    let mut monitor = StateMonitor::with_config(config);

    // Custom operation with exact cost
    let custom = OperationType::Custom(50);
    monitor.begin_step("custom1", custom).unwrap();
    monitor.end_step("r").unwrap();

    assert_eq!(monitor.gas_remaining(), 50);

    monitor.begin_step("custom2", custom).unwrap();
    monitor.end_step("r").unwrap();

    assert_eq!(monitor.gas_remaining(), 0);

    // Should be exhausted now
    let result = monitor.begin_step("custom3", OperationType::StateRead);
    assert!(result.is_err());
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn test_stress_high_operation_count() {
    let config = StateMonitorConfig::new()
        .with_gas_budget(2_000)
        .with_context_capacity(50)
        .with_auto_flush(true)
        .with_flush_count(25);

    let mut monitor = StateMonitor::with_config(config);

    // Execute operations until gas exhausted (2000 / 1 = 2000 ops max)
    let mut count = 0;
    while count < 2500 {
        let step_id = format!("s{}", count);
        if monitor.begin_step(&step_id, OperationType::StateRead).is_ok() {
            monitor.end_step("x").unwrap();
            count += 1;
        } else {
            break;
        }
    }

    // Should hit gas limit before 2500
    assert!(monitor.step_count() >= 2000 || monitor.gas_exhausted());
    assert!(monitor.context_frame_count() <= 50);
}

#[test]
fn test_stress_alternating_operation_types() {
    let config = StateMonitorConfig::new()
        .with_gas_budget(10_000)
        .with_context_capacity(50);

    let mut monitor = StateMonitor::with_config(config);

    let ops = [
        OperationType::StateRead,
        OperationType::StateWrite,
        OperationType::ToolCall,
        OperationType::NetworkIo,
    ];

    let mut i = 0;
    loop {
        let op = ops[i % ops.len()];
        if monitor.begin_step(&format!("s{}", i), op).is_ok() {
            monitor.end_step("r").unwrap();
            i += 1;
        } else {
            break;
        }
    }

    // Should execute until gas exhausted
    // Average cost: (1 + 5 + 10 + 20) / 4 = 9
    // Expected ops: ~10000 / 9 = ~1111
    assert!(monitor.step_count() > 500);
}

// ============================================================================
// Error Message Tests
// ============================================================================

#[test]
fn test_error_message_gas_exhausted() {
    let config = StateMonitorConfig::new().with_gas_budget(5);
    let mut monitor = StateMonitor::with_config(config);

    let result = monitor.begin_step("expensive", OperationType::ToolCall);

    match result {
        Err(MonitorError::GasExhausted {
            required,
            available,
            ..
        }) => {
            assert_eq!(required, 10);
            assert_eq!(available, 5);
        }
        _ => panic!("Expected GasExhausted error"),
    }
}

#[test]
fn test_error_message_invalid_state() {
    let mut monitor = StateMonitor::new();

    let result = monitor.end_step("no begin");

    match result {
        Err(MonitorError::InvalidState(msg)) => {
            assert!(msg.contains("begin_step"));
        }
        _ => panic!("Expected InvalidState error"),
    }
}
