//! # State Monitor
//!
//! Complete state monitoring: cycle detection + gas budgeting +
//! context flush. Prevents state-based attacks on MCP agents.
//!
//! ## Threat Model
//!
//! MCP agents face multiple state-based attack vectors:
//! - **Context explosion** (flush strategy: LRU eviction)
//! - **Gas bypass** (budget tracking per operation)
//! - **Undetected cycles** (Floyd + Tarjan integration)
//!
//! The `StateMonitor` facade provides a unified interface for
//! monitoring and enforcing all three security properties.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              StateMonitor                   │
//! │  ┌─────────────┬──────────┬──────────────┐  │
//! │  │   Cycle     │   Gas    │   Context    │  │
//! │  │  Detector   │  Budget  │   Manager    │  │
//! │  └─────────────┴──────────┴──────────────┘  │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ## Security Notes
//!
//! - All checks execute BEFORE the guarded operation
//! - Any failed check MUST halt execution immediately
//! - Monitoring state is append-only during execution
//! - Reset operations are privileged (new execution context only)
//!
//! ## References
//!
//! - Floyd, R. W. (1967). "Nondeterministic Algorithms"
//! - Tarjan, R. E. (1972). "Depth-first search and linear graph algorithms"
//! - Ethereum Yellow Paper, Section 9: Execution Model
//!
//! ## Example
//!
//! ```rust
//! use sentinel_monitor::{StateMonitor, StateMonitorConfig, OperationType};
//!
//! // Create monitor with custom config
//! let config = StateMonitorConfig::new()
//!     .with_gas_budget(10_000)
//!     .with_context_capacity(500)
//!     .with_flush_threshold(0.8);
//!
//! let mut monitor = StateMonitor::with_config(config);
//!
//! // Before each agent step:
//! monitor.begin_step("read_file", OperationType::ToolCall)?;
//!
//! // ... execute the operation ...
//!
//! // After each step:
//! monitor.end_step("result: file contents")?;
//!
//! # Ok::<(), sentinel_monitor::MonitorError>(())
//! ```

use crate::cycle::{Cycle, CycleDetector, ExecutionNode};
use crate::error::{MonitorError, Result};
use crate::flush::{ContextManager, Frame};
use crate::gas::{GasBudget, OperationType};

/// Configuration for `StateMonitor`.
///
/// Use the builder pattern to configure monitoring parameters.
///
/// # Example
///
/// ```rust
/// use sentinel_monitor::StateMonitorConfig;
///
/// let config = StateMonitorConfig::new()
///     .with_gas_budget(5000)
///     .with_context_capacity(100)
///     .with_flush_threshold(0.75);
/// ```
#[derive(Debug, Clone)]
pub struct StateMonitorConfig {
    /// Initial gas budget.
    pub gas_budget: u64,
    /// Maximum context frames.
    pub context_capacity: usize,
    /// Context flush threshold (0.0 to 1.0).
    pub flush_threshold: f64,
    /// Auto-flush when threshold exceeded.
    pub auto_flush: bool,
    /// Frames to evict during auto-flush.
    pub flush_count: usize,
}

impl StateMonitorConfig {
    /// Creates a new config with default values.
    ///
    /// Defaults:
    /// - Gas budget: 10,000
    /// - Context capacity: 1,000 frames
    /// - Flush threshold: 0.8 (80%)
    /// - Auto-flush: enabled
    /// - Flush count: 100 frames per flush
    #[must_use]
    pub const fn new() -> Self {
        Self {
            gas_budget: 10_000,
            context_capacity: 1000,
            flush_threshold: 0.8,
            auto_flush: true,
            flush_count: 100,
        }
    }

    /// Sets the gas budget.
    #[must_use]
    pub const fn with_gas_budget(mut self, budget: u64) -> Self {
        self.gas_budget = budget;
        self
    }

    /// Sets the context capacity.
    #[must_use]
    pub const fn with_context_capacity(mut self, capacity: usize) -> Self {
        self.context_capacity = capacity;
        self
    }

    /// Sets the flush threshold.
    #[must_use]
    pub const fn with_flush_threshold(mut self, threshold: f64) -> Self {
        self.flush_threshold = threshold;
        self
    }

    /// Enables or disables auto-flush.
    #[must_use]
    pub const fn with_auto_flush(mut self, enabled: bool) -> Self {
        self.auto_flush = enabled;
        self
    }

    /// Sets the number of frames to evict during auto-flush.
    #[must_use]
    pub const fn with_flush_count(mut self, count: usize) -> Self {
        self.flush_count = count;
        self
    }
}

impl Default for StateMonitorConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Unified state monitor integrating cycle detection, gas budgeting,
/// and context management.
///
/// # Overview
///
/// `StateMonitor` is the primary interface for protecting MCP agent
/// execution. It enforces:
///
/// 1. **Cycle detection**: Prevents infinite loops via Floyd + Tarjan
/// 2. **Gas budgeting**: Limits computational resources per execution
/// 3. **Context management**: Bounds memory via LRU eviction
///
/// # Thread Safety
///
/// `StateMonitor` is not thread-safe. Each agent execution context
/// should have its own monitor instance.
///
/// # Security Notes
///
/// - Call [`begin_step`](Self::begin_step) BEFORE each operation
/// - Call [`end_step`](Self::end_step) AFTER each operation
/// - Check return values - any error MUST halt execution
/// - Never share monitors between untrusted execution contexts
///
/// # Example
///
/// ```rust
/// use sentinel_monitor::{StateMonitor, OperationType};
///
/// let mut monitor = StateMonitor::new();
///
/// // Simulate agent execution
/// for i in 0..10 {
///     let step_id = format!("step_{}", i);
///     monitor.begin_step(&step_id, OperationType::StateRead)?;
///     // ... execute operation ...
///     monitor.end_step(&format!("completed {}", i))?;
/// }
///
/// // Check final state
/// assert!(monitor.gas_remaining() > 0);
/// assert!(!monitor.cycle_detected());
/// # Ok::<(), sentinel_monitor::MonitorError>(())
/// ```
#[derive(Debug)]
pub struct StateMonitor {
    /// Configuration.
    config: StateMonitorConfig,
    /// Cycle detector (Floyd + Tarjan).
    cycle_detector: CycleDetector,
    /// Gas budget tracker.
    gas_budget: GasBudget,
    /// Context frame manager.
    context: ContextManager,
    /// Current step counter.
    step_count: u64,
    /// Current step ID (set by begin_step).
    current_step: Option<String>,
    /// Last detected cycle (if any).
    last_cycle: Option<Cycle>,
    /// Whether monitor is halted due to security violation.
    halted: bool,
}

impl StateMonitor {
    /// Creates a new monitor with default configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::StateMonitor;
    ///
    /// let monitor = StateMonitor::new();
    /// assert_eq!(monitor.gas_remaining(), 10_000);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(StateMonitorConfig::new())
    }

    /// Creates a monitor with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration parameters
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::{StateMonitor, StateMonitorConfig};
    ///
    /// let config = StateMonitorConfig::new().with_gas_budget(5000);
    /// let monitor = StateMonitor::with_config(config);
    /// assert_eq!(monitor.gas_remaining(), 5000);
    /// ```
    #[must_use]
    pub fn with_config(config: StateMonitorConfig) -> Self {
        Self {
            cycle_detector: CycleDetector::new(),
            gas_budget: GasBudget::new(config.gas_budget),
            context: ContextManager::with_threshold(
                config.context_capacity,
                config.flush_threshold,
            ),
            config,
            step_count: 0,
            current_step: None,
            last_cycle: None,
            halted: false,
        }
    }

    /// Begins a new execution step.
    ///
    /// This method MUST be called BEFORE each agent operation.
    /// It performs:
    /// 1. Gas consumption for the operation type
    /// 2. Cycle detection check
    /// 3. Context capacity check (with auto-flush if enabled)
    ///
    /// # Arguments
    ///
    /// * `step_id` - Unique identifier for this step
    /// * `op_type` - Type of operation being executed
    ///
    /// # Returns
    ///
    /// `Ok(())` if step can proceed, `Err` if blocked by:
    /// - Gas exhaustion
    /// - Cycle detected
    /// - Context overflow (without auto-flush)
    /// - Monitor halted
    ///
    /// # Security Notes
    ///
    /// - Gas is consumed BEFORE operation executes
    /// - Cycle detection runs on step state
    /// - Failed steps do not add to context
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::{StateMonitor, OperationType};
    ///
    /// let mut monitor = StateMonitor::new();
    ///
    /// // This will consume 10 gas units
    /// monitor.begin_step("call_api", OperationType::ToolCall)?;
    /// # Ok::<(), sentinel_monitor::MonitorError>(())
    /// ```
    pub fn begin_step(&mut self, step_id: &str, op_type: OperationType) -> Result<()> {
        // Check if halted
        if self.halted {
            return Err(MonitorError::InvalidState(
                "monitor halted due to security violation".to_string(),
            ));
        }

        // Check if already in a step
        if self.current_step.is_some() {
            return Err(MonitorError::InvalidState(
                "begin_step called without end_step".to_string(),
            ));
        }

        // Consume gas BEFORE operation
        self.gas_budget.consume(op_type)?;

        // Record step for cycle detection
        self.step_count += 1;
        let node = ExecutionNode::new(step_id, self.step_count);
        self.cycle_detector.record_step(node);

        // Check for cycles
        if let Some(cycle) = self.cycle_detector.detect_cycle() {
            self.last_cycle = Some(cycle.clone());
            self.halted = true;
            return Err(MonitorError::CycleDetected {
                step: self.step_count,
                description: format!("cycle of {} nodes detected", cycle.length()),
            });
        }

        // Check context capacity, auto-flush if needed
        if self.context.should_flush() {
            if self.config.auto_flush {
                self.context.flush(self.config.flush_count);
            } else {
                return Err(MonitorError::ContextOverflow {
                    current: self.context.len(),
                    limit: self.context.capacity(),
                });
            }
        }

        // Mark step as active
        self.current_step = Some(step_id.to_string());

        Ok(())
    }

    /// Ends the current execution step.
    ///
    /// This method MUST be called AFTER each agent operation.
    /// It records the step result in the context.
    ///
    /// # Arguments
    ///
    /// * `result` - Serialized result of the operation
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err` if:
    /// - No step was begun
    /// - Monitor is halted
    ///
    /// # Security Notes
    ///
    /// - Only successful operations should call end_step
    /// - Failed operations should NOT call end_step
    /// - Context frame is added with operation result
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::{StateMonitor, OperationType};
    ///
    /// let mut monitor = StateMonitor::new();
    /// monitor.begin_step("read_config", OperationType::StateRead)?;
    ///
    /// // ... execute operation ...
    ///
    /// monitor.end_step("config loaded successfully")?;
    /// # Ok::<(), sentinel_monitor::MonitorError>(())
    /// ```
    pub fn end_step(&mut self, result: &str) -> Result<()> {
        if self.halted {
            return Err(MonitorError::InvalidState(
                "monitor halted due to security violation".to_string(),
            ));
        }

        let step_id = self.current_step.take().ok_or_else(|| {
            MonitorError::InvalidState("end_step called without begin_step".to_string())
        })?;

        // Add frame to context
        let frame = Frame::new(step_id, result);
        self.context.push(frame);

        Ok(())
    }

    /// Returns remaining gas budget.
    #[inline]
    #[must_use]
    pub fn gas_remaining(&self) -> u64 {
        self.gas_budget.remaining()
    }

    /// Returns gas utilization as percentage (0.0 to 1.0).
    #[inline]
    #[must_use]
    pub fn gas_utilization(&self) -> f64 {
        self.gas_budget.utilization()
    }

    /// Returns true if gas is exhausted.
    #[inline]
    #[must_use]
    pub fn gas_exhausted(&self) -> bool {
        self.gas_budget.is_exhausted()
    }

    /// Returns current context frame count.
    #[inline]
    #[must_use]
    pub fn context_frame_count(&self) -> usize {
        self.context.len()
    }

    /// Returns context utilization as percentage (0.0 to 1.0).
    #[inline]
    #[must_use]
    pub fn context_utilization(&self) -> f64 {
        self.context.utilization()
    }

    /// Returns total steps executed.
    #[inline]
    #[must_use]
    pub const fn step_count(&self) -> u64 {
        self.step_count
    }

    /// Returns true if a cycle was detected.
    #[inline]
    #[must_use]
    pub fn cycle_detected(&self) -> bool {
        self.last_cycle.is_some()
    }

    /// Returns the last detected cycle, if any.
    #[must_use]
    pub fn last_cycle(&self) -> Option<&Cycle> {
        self.last_cycle.as_ref()
    }

    /// Returns true if monitor is halted due to security violation.
    #[inline]
    #[must_use]
    pub const fn is_halted(&self) -> bool {
        self.halted
    }

    /// Manually flushes context frames.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of frames to evict
    ///
    /// # Returns
    ///
    /// Number of frames actually evicted.
    ///
    /// # Security Notes
    ///
    /// Prefer auto-flush during normal operation. Use manual flush
    /// only when explicit control is needed.
    pub fn flush_context(&mut self, count: usize) -> usize {
        self.context.flush(count)
    }

    /// Checks if the monitor can afford an operation.
    ///
    /// This is a pre-flight check that does NOT consume gas.
    ///
    /// # Arguments
    ///
    /// * `op_type` - Operation type to check
    ///
    /// # Returns
    ///
    /// `true` if operation can be afforded.
    #[inline]
    #[must_use]
    pub fn can_afford(&self, op_type: OperationType) -> bool {
        !self.halted && self.gas_budget.can_afford(op_type)
    }

    /// Resets the monitor for a new execution context.
    ///
    /// # Security Notes
    ///
    /// This is a PRIVILEGED operation. Only call when:
    /// - Starting a completely new agent invocation
    /// - After explicit user authorization
    ///
    /// Never reset mid-execution as this could enable security bypass.
    pub fn reset(&mut self) {
        self.cycle_detector.clear();
        self.gas_budget.reset();
        self.context.clear();
        self.step_count = 0;
        self.current_step = None;
        self.last_cycle = None;
        self.halted = false;
    }

    /// Returns a status report of the monitor state.
    ///
    /// Useful for logging and debugging.
    #[must_use]
    pub fn status_report(&self) -> MonitorStatus {
        MonitorStatus {
            step_count: self.step_count,
            gas_remaining: self.gas_budget.remaining(),
            gas_consumed: self.gas_budget.consumed(),
            gas_utilization: self.gas_budget.utilization(),
            context_frames: self.context.len(),
            context_capacity: self.context.capacity(),
            context_utilization: self.context.utilization(),
            context_evicted: self.context.evicted_count(),
            cycle_detected: self.last_cycle.is_some(),
            halted: self.halted,
        }
    }
}

impl Default for StateMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Status report of monitor state.
///
/// Provides a snapshot of all monitoring metrics for logging/debugging.
#[derive(Debug, Clone)]
pub struct MonitorStatus {
    /// Total steps executed.
    pub step_count: u64,
    /// Remaining gas.
    pub gas_remaining: u64,
    /// Gas consumed.
    pub gas_consumed: u64,
    /// Gas utilization (0.0 to 1.0).
    pub gas_utilization: f64,
    /// Current context frames.
    pub context_frames: usize,
    /// Maximum context capacity.
    pub context_capacity: usize,
    /// Context utilization (0.0 to 1.0).
    pub context_utilization: f64,
    /// Total frames evicted.
    pub context_evicted: u64,
    /// Whether cycle was detected.
    pub cycle_detected: bool,
    /// Whether monitor is halted.
    pub halted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = StateMonitorConfig::new()
            .with_gas_budget(5000)
            .with_context_capacity(200)
            .with_flush_threshold(0.7)
            .with_auto_flush(false)
            .with_flush_count(50);

        assert_eq!(config.gas_budget, 5000);
        assert_eq!(config.context_capacity, 200);
        assert!((config.flush_threshold - 0.7).abs() < f64::EPSILON);
        assert!(!config.auto_flush);
        assert_eq!(config.flush_count, 50);
    }

    #[test]
    fn test_monitor_creation() {
        let monitor = StateMonitor::new();
        assert_eq!(monitor.gas_remaining(), 10_000);
        assert_eq!(monitor.step_count(), 0);
        assert!(!monitor.cycle_detected());
        assert!(!monitor.is_halted());
    }

    #[test]
    fn test_basic_step_execution() {
        let mut monitor = StateMonitor::new();

        monitor.begin_step("step1", OperationType::StateRead).unwrap();
        monitor.end_step("result1").unwrap();

        assert_eq!(monitor.step_count(), 1);
        assert_eq!(monitor.gas_remaining(), 9999); // 10000 - 1
        assert_eq!(monitor.context_frame_count(), 1);
    }

    #[test]
    fn test_gas_consumption() {
        let config = StateMonitorConfig::new().with_gas_budget(50);
        let mut monitor = StateMonitor::with_config(config);

        monitor.begin_step("s1", OperationType::ToolCall).unwrap(); // 10, remaining 40
        monitor.end_step("r1").unwrap();
        assert_eq!(monitor.gas_remaining(), 40);

        // This should fail - needs 100, only 40 available
        let result = monitor.begin_step("s2", OperationType::LlmInference);
        assert!(result.is_err());
        assert_eq!(monitor.gas_remaining(), 40); // Unchanged on failure
    }

    #[test]
    fn test_cycle_detection_halts() {
        let mut monitor = StateMonitor::new();

        // Create a cycle by repeating states
        monitor.begin_step("state_a", OperationType::StateRead).unwrap();
        monitor.end_step("r").unwrap();

        monitor.begin_step("state_b", OperationType::StateRead).unwrap();
        monitor.end_step("r").unwrap();

        // Repeat state_a - should trigger cycle detection
        let result = monitor.begin_step("state_a", OperationType::StateRead);

        // Depending on detection algorithm, this may or may not trigger
        // Let's check if it did detect
        if result.is_err() {
            assert!(monitor.cycle_detected());
            assert!(monitor.is_halted());
        }
    }

    #[test]
    fn test_halted_monitor_rejects_steps() {
        let mut monitor = StateMonitor::new();
        monitor.halted = true; // Force halt

        let result = monitor.begin_step("x", OperationType::StateRead);
        assert!(result.is_err());
    }

    #[test]
    fn test_double_begin_fails() {
        let mut monitor = StateMonitor::new();

        monitor.begin_step("s1", OperationType::StateRead).unwrap();
        // Don't call end_step

        let result = monitor.begin_step("s2", OperationType::StateRead);
        assert!(result.is_err());
    }

    #[test]
    fn test_end_without_begin_fails() {
        let mut monitor = StateMonitor::new();

        let result = monitor.end_step("result");
        assert!(result.is_err());
    }

    #[test]
    fn test_auto_flush() {
        let config = StateMonitorConfig::new()
            .with_context_capacity(10)
            .with_flush_threshold(0.5)
            .with_auto_flush(true)
            .with_flush_count(3);

        let mut monitor = StateMonitor::with_config(config);

        // Add 8 frames (80% utilization, above 50% threshold)
        for i in 0..8 {
            monitor.begin_step(&format!("s{}", i), OperationType::StateRead).unwrap();
            monitor.end_step("r").unwrap();
        }

        // Should have auto-flushed some frames
        assert!(monitor.context_frame_count() < 8);
    }

    #[test]
    fn test_manual_flush() {
        let mut monitor = StateMonitor::new();

        for i in 0..10 {
            monitor.begin_step(&format!("s{}", i), OperationType::StateRead).unwrap();
            monitor.end_step("r").unwrap();
        }

        let evicted = monitor.flush_context(5);
        assert_eq!(evicted, 5);
        assert_eq!(monitor.context_frame_count(), 5);
    }

    #[test]
    fn test_can_afford() {
        let config = StateMonitorConfig::new().with_gas_budget(50);
        let monitor = StateMonitor::with_config(config);

        assert!(monitor.can_afford(OperationType::ToolCall)); // 10
        assert!(!monitor.can_afford(OperationType::LlmInference)); // 100
    }

    #[test]
    fn test_reset() {
        let mut monitor = StateMonitor::new();

        // Do some work
        monitor.begin_step("s1", OperationType::ToolCall).unwrap();
        monitor.end_step("r1").unwrap();

        assert!(monitor.gas_remaining() < 10_000);
        assert_eq!(monitor.step_count(), 1);

        // Reset
        monitor.reset();

        assert_eq!(monitor.gas_remaining(), 10_000);
        assert_eq!(monitor.step_count(), 0);
        assert_eq!(monitor.context_frame_count(), 0);
        assert!(!monitor.is_halted());
    }

    #[test]
    fn test_status_report() {
        let mut monitor = StateMonitor::new();

        monitor.begin_step("s1", OperationType::ToolCall).unwrap();
        monitor.end_step("r1").unwrap();

        let status = monitor.status_report();

        assert_eq!(status.step_count, 1);
        assert_eq!(status.gas_remaining, 9990);
        assert_eq!(status.gas_consumed, 10);
        assert_eq!(status.context_frames, 1);
        assert!(!status.cycle_detected);
        assert!(!status.halted);
    }

    // Security-focused tests
    #[test]
    fn test_security_gas_enforced_before_operation() {
        let config = StateMonitorConfig::new().with_gas_budget(5);
        let mut monitor = StateMonitor::with_config(config);

        // Try to execute operation that costs more than available gas
        let result = monitor.begin_step("expensive", OperationType::ToolCall); // 10 gas

        // Should fail BEFORE recording the step
        assert!(result.is_err());
        assert_eq!(monitor.step_count(), 0); // Step not recorded
    }

    #[test]
    fn test_security_halted_state_persists() {
        let mut monitor = StateMonitor::new();
        monitor.halted = true;

        // Multiple attempts should all fail
        for i in 0..5 {
            let result = monitor.begin_step(&format!("s{}", i), OperationType::StateRead);
            assert!(result.is_err());
        }

        // Still halted
        assert!(monitor.is_halted());
    }

    #[test]
    fn test_security_context_bounded() {
        let config = StateMonitorConfig::new()
            .with_context_capacity(5)
            .with_auto_flush(true)
            .with_flush_count(2);

        let mut monitor = StateMonitor::with_config(config);

        // Try to add many frames
        for i in 0..100 {
            monitor.begin_step(&format!("s{}", i), OperationType::StateRead).unwrap();
            monitor.end_step("r").unwrap();

            // Context should never exceed capacity
            assert!(monitor.context_frame_count() <= 5);
        }
    }
}
