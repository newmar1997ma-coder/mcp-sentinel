//! # Gas Budget System
//!
//! Enforces computational limits on MCP agent operations to prevent
//! resource exhaustion attacks and ensure fair resource allocation.
//!
//! ## Threat Model
//!
//! Without gas budgeting, malicious or buggy agents can:
//! - **CPU exhaustion**: Execute expensive operations indefinitely
//! - **Memory exhaustion**: Allocate unbounded resources
//! - **Budget bypass**: Craft operations that circumvent limits
//!
//! ## Design
//!
//! Gas is an abstract unit of computational cost. Each operation type
//! has a fixed gas cost. Before executing any operation, the agent
//! must check if sufficient gas remains. Gas enforcement MUST happen
//! BEFORE operation execution to prevent budget bypass attacks.
//!
//! ## Cost Model
//!
//! | Operation Type | Gas Cost | Rationale |
//! |---------------|----------|-----------|
//! | State Read    | 1        | Cheap memory access |
//! | State Write   | 5        | Mutation is expensive |
//! | Tool Call     | 10       | External interaction |
//! | LLM Inference | 100      | Most expensive operation |
//! | Network I/O   | 20       | Blocking external call |
//!
//! ## Security Notes
//!
//! - Gas check MUST occur BEFORE operation, never after
//! - Gas costs are non-negotiable once set
//! - Budget cannot be increased during execution (only reset)
//! - All gas exhaustion events are logged for forensic analysis
//!
//! ## Example
//!
//! ```rust
//! use sentinel_monitor::{GasBudget, OperationType};
//!
//! // Create budget with 1000 gas units
//! let mut budget = GasBudget::new(1000);
//!
//! // Check before each operation
//! if budget.consume(OperationType::ToolCall).is_ok() {
//!     // Execute the tool call
//! } else {
//!     // Gas exhausted - halt execution
//! }
//! ```
//!
//! ## References
//!
//! - Ethereum Yellow Paper, Section 9: Execution Model (gas semantics)
//! - Wood, G. (2014). "Ethereum: A Secure Decentralised Generalised Transaction Ledger"

use crate::error::{MonitorError, Result};

/// Operation types with associated gas costs.
///
/// Each operation type has a fixed, immutable gas cost designed
/// to reflect its computational expense and security impact.
///
/// # Security Notes
///
/// Gas costs are calibrated to prevent:
/// - Cheap operations flooding the system
/// - Expensive operations starving resources
/// - Attackers gaming cost differentials
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// Reading state from memory/storage.
    /// Cost: 1 gas (cheapest operation).
    StateRead,

    /// Writing/mutating state.
    /// Cost: 5 gas (mutations require validation).
    StateWrite,

    /// Invoking an external tool.
    /// Cost: 10 gas (external calls have side effects).
    ToolCall,

    /// Making an LLM inference request.
    /// Cost: 100 gas (most expensive due to compute).
    LlmInference,

    /// Performing network I/O.
    /// Cost: 20 gas (blocking external dependency).
    NetworkIo,

    /// Custom operation with specified cost.
    /// Use for domain-specific operations not covered above.
    Custom(u64),
}

impl OperationType {
    /// Returns the gas cost for this operation type.
    ///
    /// # Security Notes
    ///
    /// Costs are immutable once compiled. This prevents runtime
    /// manipulation of gas costs by malicious actors.
    #[inline]
    #[must_use]
    pub const fn cost(&self) -> u64 {
        match self {
            Self::StateRead => 1,
            Self::StateWrite => 5,
            Self::ToolCall => 10,
            Self::LlmInference => 100,
            Self::NetworkIo => 20,
            Self::Custom(cost) => *cost,
        }
    }
}

/// Tracks and enforces gas budget for agent operations.
///
/// # Overview
///
/// `GasBudget` maintains a monotonically decreasing gas counter.
/// Before each operation, the agent must call [`consume`](Self::consume)
/// to deduct gas. If insufficient gas remains, the operation is denied.
///
/// # Thread Safety
///
/// `GasBudget` is not thread-safe. Each agent execution context
/// should have its own budget instance.
///
/// # Security Notes
///
/// - **Pre-execution enforcement**: Gas is deducted BEFORE operation runs
/// - **No overdraft**: Operations fail immediately if gas insufficient
/// - **Audit trail**: All consumption is trackable via remaining()
///
/// # Example
///
/// ```rust
/// use sentinel_monitor::{GasBudget, OperationType};
///
/// let mut budget = GasBudget::new(50);
///
/// // Consume gas for a tool call (10 gas)
/// assert!(budget.consume(OperationType::ToolCall).is_ok());
/// assert_eq!(budget.remaining(), 40);
///
/// // Try to consume 100 gas for LLM inference - fails
/// assert!(budget.consume(OperationType::LlmInference).is_err());
/// assert_eq!(budget.remaining(), 40); // Unchanged on failure
/// ```
#[derive(Debug, Clone)]
pub struct GasBudget {
    /// Initial gas allocation (immutable after creation).
    initial: u64,
    /// Current remaining gas.
    remaining: u64,
    /// Total gas consumed so far.
    consumed: u64,
    /// Count of operations executed.
    operation_count: u64,
}

impl GasBudget {
    /// Creates a new gas budget with the specified initial allocation.
    ///
    /// # Arguments
    ///
    /// * `initial_gas` - Total gas units available for this execution context
    ///
    /// # Security Notes
    ///
    /// Choose initial gas carefully:
    /// - Too low: Legitimate operations fail
    /// - Too high: Resource exhaustion possible
    /// - Recommended: Profile typical agent workloads
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::GasBudget;
    ///
    /// let budget = GasBudget::new(10_000);
    /// assert_eq!(budget.remaining(), 10_000);
    /// ```
    #[must_use]
    pub const fn new(initial_gas: u64) -> Self {
        Self {
            initial: initial_gas,
            remaining: initial_gas,
            consumed: 0,
            operation_count: 0,
        }
    }

    /// Returns the initial gas allocation.
    #[inline]
    #[must_use]
    pub const fn initial(&self) -> u64 {
        self.initial
    }

    /// Returns the remaining gas available.
    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Returns the total gas consumed so far.
    #[inline]
    #[must_use]
    pub const fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Returns the count of operations executed.
    #[inline]
    #[must_use]
    pub const fn operation_count(&self) -> u64 {
        self.operation_count
    }

    /// Returns the gas utilization as a percentage (0.0 to 1.0).
    ///
    /// # Returns
    ///
    /// Fraction of initial gas that has been consumed.
    /// Returns 0.0 if initial gas was 0 (prevents division by zero).
    #[inline]
    #[must_use]
    pub fn utilization(&self) -> f64 {
        if self.initial == 0 {
            0.0
        } else {
            self.consumed as f64 / self.initial as f64
        }
    }

    /// Checks if the budget can afford the specified operation.
    ///
    /// # Arguments
    ///
    /// * `op` - Operation type to check
    ///
    /// # Returns
    ///
    /// `true` if sufficient gas remains for the operation.
    ///
    /// # Security Notes
    ///
    /// Use this for pre-flight checks. Always follow with `consume()`
    /// for actual execution to ensure atomicity.
    #[inline]
    #[must_use]
    pub fn can_afford(&self, op: OperationType) -> bool {
        self.remaining >= op.cost()
    }

    /// Consumes gas for the specified operation.
    ///
    /// # Arguments
    ///
    /// * `op` - Operation type being executed
    ///
    /// # Returns
    ///
    /// - `Ok(remaining)` - Gas consumed, returns remaining balance
    /// - `Err(GasExhausted)` - Insufficient gas, operation denied
    ///
    /// # Security Notes
    ///
    /// - Gas is ONLY deducted on success
    /// - On failure, budget remains unchanged (no partial deduction)
    /// - This MUST be called BEFORE operation execution
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::{GasBudget, OperationType};
    ///
    /// let mut budget = GasBudget::new(10);
    ///
    /// // Successful consumption
    /// let remaining = budget.consume(OperationType::StateRead)?;
    /// assert_eq!(remaining, 9);
    ///
    /// # Ok::<(), sentinel_monitor::MonitorError>(())
    /// ```
    pub fn consume(&mut self, op: OperationType) -> Result<u64> {
        let cost = op.cost();

        if self.remaining < cost {
            return Err(MonitorError::GasExhausted {
                required: cost,
                available: self.remaining,
                operation: format!("{:?}", op),
            });
        }

        self.remaining -= cost;
        self.consumed += cost;
        self.operation_count += 1;

        Ok(self.remaining)
    }

    /// Consumes a specific amount of gas directly.
    ///
    /// # Arguments
    ///
    /// * `amount` - Gas units to consume
    ///
    /// # Returns
    ///
    /// - `Ok(remaining)` - Gas consumed successfully
    /// - `Err(GasExhausted)` - Insufficient gas
    ///
    /// # Security Notes
    ///
    /// Prefer [`consume`](Self::consume) with typed operations when possible.
    /// This method is for custom/dynamic gas costs only.
    pub fn consume_raw(&mut self, amount: u64) -> Result<u64> {
        if self.remaining < amount {
            return Err(MonitorError::GasExhausted {
                required: amount,
                available: self.remaining,
                operation: "raw consumption".to_string(),
            });
        }

        self.remaining -= amount;
        self.consumed += amount;
        self.operation_count += 1;

        Ok(self.remaining)
    }

    /// Resets the budget to initial allocation.
    ///
    /// # Security Notes
    ///
    /// Budget reset is a privileged operation. Only call this when
    /// starting a new execution context (e.g., new agent invocation).
    /// Never reset mid-execution as this could enable budget bypass.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::{GasBudget, OperationType};
    ///
    /// let mut budget = GasBudget::new(100);
    /// budget.consume(OperationType::StateWrite)?;
    /// assert_eq!(budget.remaining(), 95);
    ///
    /// budget.reset();
    /// assert_eq!(budget.remaining(), 100);
    /// # Ok::<(), sentinel_monitor::MonitorError>(())
    /// ```
    pub fn reset(&mut self) {
        self.remaining = self.initial;
        self.consumed = 0;
        self.operation_count = 0;
    }

    /// Returns true if the budget is completely exhausted.
    #[inline]
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.remaining == 0
    }
}

impl Default for GasBudget {
    /// Creates a budget with default allocation of 10,000 gas units.
    ///
    /// This default is suitable for typical agent workloads:
    /// - ~100 LLM inferences, or
    /// - ~1000 tool calls, or
    /// - ~10000 state reads
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_costs() {
        assert_eq!(OperationType::StateRead.cost(), 1);
        assert_eq!(OperationType::StateWrite.cost(), 5);
        assert_eq!(OperationType::ToolCall.cost(), 10);
        assert_eq!(OperationType::LlmInference.cost(), 100);
        assert_eq!(OperationType::NetworkIo.cost(), 20);
        assert_eq!(OperationType::Custom(42).cost(), 42);
    }

    #[test]
    fn test_budget_creation() {
        let budget = GasBudget::new(1000);
        assert_eq!(budget.initial(), 1000);
        assert_eq!(budget.remaining(), 1000);
        assert_eq!(budget.consumed(), 0);
        assert_eq!(budget.operation_count(), 0);
    }

    #[test]
    fn test_successful_consumption() {
        let mut budget = GasBudget::new(100);

        let remaining = budget.consume(OperationType::StateRead).unwrap();
        assert_eq!(remaining, 99);
        assert_eq!(budget.consumed(), 1);
        assert_eq!(budget.operation_count(), 1);

        let remaining = budget.consume(OperationType::ToolCall).unwrap();
        assert_eq!(remaining, 89);
        assert_eq!(budget.consumed(), 11);
        assert_eq!(budget.operation_count(), 2);
    }

    #[test]
    fn test_gas_exhaustion() {
        let mut budget = GasBudget::new(50);

        // LLM inference costs 100, budget only has 50
        let result = budget.consume(OperationType::LlmInference);
        assert!(result.is_err());

        // Budget should remain unchanged on failure
        assert_eq!(budget.remaining(), 50);
        assert_eq!(budget.consumed(), 0);
        assert_eq!(budget.operation_count(), 0);
    }

    #[test]
    fn test_can_afford() {
        let budget = GasBudget::new(15);

        assert!(budget.can_afford(OperationType::StateRead));
        assert!(budget.can_afford(OperationType::ToolCall));
        assert!(!budget.can_afford(OperationType::LlmInference));
    }

    #[test]
    fn test_utilization() {
        let mut budget = GasBudget::new(100);
        assert_eq!(budget.utilization(), 0.0);

        budget.consume(OperationType::ToolCall).unwrap(); // 10 gas
        assert!((budget.utilization() - 0.1).abs() < f64::EPSILON);

        budget.consume(OperationType::LlmInference).ok(); // Fails - insufficient
        assert!((budget.utilization() - 0.1).abs() < f64::EPSILON); // Unchanged
    }

    #[test]
    fn test_zero_budget_utilization() {
        let budget = GasBudget::new(0);
        assert_eq!(budget.utilization(), 0.0); // No division by zero
    }

    #[test]
    fn test_reset() {
        let mut budget = GasBudget::new(100);
        budget.consume(OperationType::StateWrite).unwrap();
        budget.consume(OperationType::ToolCall).unwrap();

        assert_eq!(budget.remaining(), 85);
        assert_eq!(budget.consumed(), 15);
        assert_eq!(budget.operation_count(), 2);

        budget.reset();

        assert_eq!(budget.remaining(), 100);
        assert_eq!(budget.consumed(), 0);
        assert_eq!(budget.operation_count(), 0);
    }

    #[test]
    fn test_is_exhausted() {
        let mut budget = GasBudget::new(5);
        assert!(!budget.is_exhausted());

        budget.consume(OperationType::StateWrite).unwrap(); // Exactly 5 gas
        assert!(budget.is_exhausted());
    }

    #[test]
    fn test_consume_raw() {
        let mut budget = GasBudget::new(100);

        let remaining = budget.consume_raw(25).unwrap();
        assert_eq!(remaining, 75);

        let result = budget.consume_raw(100);
        assert!(result.is_err());
        assert_eq!(budget.remaining(), 75); // Unchanged
    }

    #[test]
    fn test_default_budget() {
        let budget = GasBudget::default();
        assert_eq!(budget.initial(), 10_000);
    }

    #[test]
    fn test_custom_operation() {
        let mut budget = GasBudget::new(100);
        let custom = OperationType::Custom(33);

        assert_eq!(custom.cost(), 33);
        let remaining = budget.consume(custom).unwrap();
        assert_eq!(remaining, 67);
    }

    // Security-focused tests
    #[test]
    fn test_security_no_negative_remaining() {
        let mut budget = GasBudget::new(5);
        budget.consume(OperationType::StateRead).unwrap(); // 1
        budget.consume(OperationType::StateRead).unwrap(); // 1
        budget.consume(OperationType::StateRead).unwrap(); // 1
        budget.consume(OperationType::StateRead).unwrap(); // 1
        budget.consume(OperationType::StateRead).unwrap(); // 1

        // Budget is now 0
        assert!(budget.is_exhausted());
        assert_eq!(budget.remaining(), 0);

        // Attempting any operation should fail
        assert!(budget.consume(OperationType::StateRead).is_err());
        assert_eq!(budget.remaining(), 0); // Still 0, not negative
    }

    #[test]
    fn test_security_budget_immutability() {
        let budget = GasBudget::new(1000);
        // initial() returns the same value regardless of consumption
        assert_eq!(budget.initial(), 1000);

        let mut budget = budget;
        budget.consume(OperationType::LlmInference).unwrap();
        assert_eq!(budget.initial(), 1000); // Still 1000
    }

    #[test]
    fn test_security_exhaustion_under_load() {
        let mut budget = GasBudget::new(1000);

        // Simulate rapid operations
        for _ in 0..100 {
            let _ = budget.consume(OperationType::ToolCall);
        }

        // Should have consumed exactly 1000 gas (100 * 10)
        assert!(budget.is_exhausted());
        assert_eq!(budget.consumed(), 1000);
        assert_eq!(budget.operation_count(), 100);
    }
}
