//! The unified Sentinel facade.
//!
//! This module provides the main entry point for the MCP Sentinel security system.
//! The [`Sentinel`] struct orchestrates all security components and provides a
//! simple API for analyzing MCP messages.

use crate::{
    config::SentinelConfig,
    error::SentinelError,
    verdict::{BlockReason, ReviewFlag, Verdict},
    Result,
};

use sentinel_council::{ActionProposal, CognitiveCouncil, CouncilVerdict};
use sentinel_monitor::{OperationType, StateMonitor, StateMonitorConfig};
use sentinel_registry::{RegistryGuard, ToolSchema, VerifyResult};

use tracing::{debug, info, warn};

/// The unified MCP Sentinel security facade.
///
/// Sentinel orchestrates three security components:
/// - **Registry Guard**: Verifies tool schema integrity
/// - **State Monitor**: Tracks execution state (cycles, gas, context)
/// - **Cognitive Council**: Evaluates action safety via consensus voting
///
/// # Security Model
///
/// The analysis pipeline is:
/// 1. Registry verification (schema integrity)
/// 2. State monitoring (resource limits)
/// 3. Council evaluation (alignment verification)
///
/// Any component can block execution. The pipeline is fail-closed:
/// errors result in Block verdicts, not Allow.
///
/// # Example
///
/// ```rust,ignore
/// let sentinel = Sentinel::new(SentinelConfig::default())?;
///
/// // Analyze a tool call
/// let verdict = sentinel.analyze_tool_call("read_file", &schema, &params)?;
///
/// if verdict.is_allowed() {
///     // Safe to execute
/// }
/// ```
pub struct Sentinel {
    /// Configuration.
    config: SentinelConfig,

    /// Registry Guard for schema verification.
    registry: RegistryGuard,

    /// State Monitor for execution tracking.
    monitor: StateMonitor,

    /// Cognitive Council for alignment verification.
    council: CognitiveCouncil,
}

impl Sentinel {
    /// Create a new Sentinel with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Registry database cannot be opened
    /// - Configuration is invalid
    pub fn new(config: SentinelConfig) -> Result<Self> {
        let registry = RegistryGuard::new(&config.registry.db_path)
            .map_err(|e| SentinelError::Registry(e.to_string()))?;

        // Configure state monitor from SentinelConfig
        let monitor_config = StateMonitorConfig::new()
            .with_gas_budget(config.monitor.gas_limit)
            .with_context_capacity(config.monitor.max_context_bytes / 1000) // Approximate frames
            .with_auto_flush(true);

        let monitor = StateMonitor::with_config(monitor_config);
        let council = CognitiveCouncil::new();

        info!(
            "Sentinel initialized with {} gas limit",
            config.monitor.gas_limit
        );

        Ok(Self {
            config,
            registry,
            monitor,
            council,
        })
    }

    /// Analyze a tool call for security threats.
    ///
    /// This runs the full security pipeline:
    /// 1. Registry verification (is the tool schema valid?)
    /// 2. State monitoring (are we in a safe state?)
    /// 3. Council evaluation (is this action aligned?)
    ///
    /// # Arguments
    ///
    /// * `tool_name` - The name of the tool being called
    /// * `schema` - The tool's schema (for verification)
    /// * `params` - The parameters being passed to the tool
    ///
    /// # Returns
    ///
    /// A [`Verdict`] indicating whether the call should be allowed, blocked, or reviewed.
    pub fn analyze_tool_call(
        &mut self,
        tool_name: &str,
        schema: &ToolSchema,
        params: &serde_json::Value,
    ) -> Result<Verdict> {
        debug!("Analyzing tool call: {}", tool_name);

        // Phase 1: Registry verification
        let registry_verdict = self.check_registry(tool_name, schema)?;
        if let Some(verdict) = registry_verdict {
            if self.config.global.short_circuit && verdict.is_blocked() {
                return Ok(verdict);
            }
        }

        // Phase 2: State monitoring (includes cycle detection)
        let monitor_verdict = self.check_monitor(tool_name)?;
        if let Some(verdict) = monitor_verdict {
            if self.config.global.short_circuit && verdict.is_blocked() {
                return Ok(verdict);
            }
        }

        // Phase 3: Council evaluation
        let council_verdict = self.check_council(tool_name, params)?;
        if let Some(verdict) = council_verdict {
            return Ok(verdict);
        }

        // All checks passed
        info!("Tool call '{}' approved by Sentinel", tool_name);
        Ok(Verdict::allow())
    }

    /// Check schema integrity with the Registry Guard.
    fn check_registry(&mut self, tool_name: &str, schema: &ToolSchema) -> Result<Option<Verdict>> {
        debug!("Registry check for: {}", tool_name);

        // Verify the tool schema
        match self.registry.verify_tool(schema) {
            VerifyResult::Valid => {
                debug!("Schema verified for: {}", tool_name);
                Ok(None)
            }
            VerifyResult::Invalid { expected, actual } => {
                warn!(
                    "Hash mismatch for '{}': expected {:?}, got {:?}",
                    tool_name, expected, actual
                );
                Ok(Some(Verdict::block(BlockReason::HashMismatch {
                    tool_name: tool_name.to_string(),
                    expected: format!("{:?}", expected),
                    actual: format!("{:?}", actual),
                })))
            }
            VerifyResult::Unknown => {
                if self.config.registry.allow_unknown_tools {
                    debug!("Unknown tool '{}' allowed by config", tool_name);
                    Ok(Some(Verdict::review(vec![ReviewFlag::NewTool {
                        tool_name: tool_name.to_string(),
                    }])))
                } else {
                    warn!("Unknown tool blocked: {}", tool_name);
                    Ok(Some(Verdict::block(BlockReason::UnknownTool {
                        tool_name: tool_name.to_string(),
                    })))
                }
            }
        }
    }

    /// Check execution state with the State Monitor.
    ///
    /// This also performs cycle detection - cycles are detected inside begin_step().
    fn check_monitor(&mut self, tool_name: &str) -> Result<Option<Verdict>> {
        debug!("Monitor check for: {}", tool_name);

        // Begin a new step - this consumes gas and checks for cycles
        match self.monitor.begin_step(tool_name, OperationType::ToolCall) {
            Ok(()) => {}
            Err(sentinel_monitor::MonitorError::GasExhausted {
                required,
                available,
                ..
            }) => {
                warn!("Gas exhausted: need {}, have {}", required, available);
                return Ok(Some(Verdict::block(BlockReason::GasExhausted {
                    used: self.config.monitor.gas_limit - available,
                    limit: self.config.monitor.gas_limit,
                })));
            }
            Err(sentinel_monitor::MonitorError::CycleDetected { step, description }) => {
                warn!("Cycle detected at step {}: {}", step, description);
                return Ok(Some(Verdict::block(BlockReason::CycleDetected {
                    cycle: description,
                })));
            }
            Err(sentinel_monitor::MonitorError::ContextOverflow { current, limit }) => {
                warn!("Context overflow: {} exceeds {}", current, limit);
                return Ok(Some(Verdict::block(BlockReason::ContextOverflow {
                    size: current,
                    max: limit,
                })));
            }
            Err(e) => {
                return Err(SentinelError::Monitor(e));
            }
        }

        // Check for high gas usage (>80%)
        let gas_remaining = self.monitor.gas_remaining();
        let gas_limit = self.config.monitor.gas_limit;
        let gas_used = gas_limit.saturating_sub(gas_remaining);
        let usage_pct = ((gas_used as f64 / gas_limit as f64) * 100.0) as u8;

        if usage_pct > 80 {
            debug!("High gas usage: {}%", usage_pct);
            return Ok(Some(Verdict::review(vec![ReviewFlag::HighGasUsage {
                percentage: usage_pct,
            }])));
        }

        Ok(None)
    }

    /// Evaluate action safety with the Cognitive Council.
    fn check_council(
        &self,
        tool_name: &str,
        params: &serde_json::Value,
    ) -> Result<Option<Verdict>> {
        debug!("Council check for: {}", tool_name);

        let proposal = ActionProposal::new(tool_name, params.to_string());

        match self.council.evaluate(&proposal) {
            CouncilVerdict::Approved {
                tally: _,
                waluigi_score: _,
            } => {
                debug!("Council approved: {}", tool_name);
                Ok(None)
            }
            CouncilVerdict::Rejected {
                reason,
                tally,
                waluigi_score: _,
            } => {
                warn!("Council rejected '{}': {}", tool_name, reason);
                Ok(Some(Verdict::block(BlockReason::CouncilRejected {
                    votes: format!("{:?}", tally),
                    reason,
                })))
            }
            CouncilVerdict::WaluigiVeto { score, patterns } => {
                warn!("Waluigi effect detected for '{}': {:?}", tool_name, score);
                Ok(Some(Verdict::block(BlockReason::WaluigiEffect {
                    score: score.value(),
                    patterns,
                })))
            }
            CouncilVerdict::NoConsensus { tally, reason } => {
                debug!("No consensus for '{}': {}", tool_name, reason);
                Ok(Some(Verdict::review(vec![ReviewFlag::SplitVote {
                    votes: format!("{:?}", tally),
                }])))
            }
        }
    }

    /// Register a tool schema with the Registry Guard.
    ///
    /// This should be called during initialization to register known-good schemas.
    pub fn register_tool(&mut self, schema: &ToolSchema) -> Result<()> {
        self.registry
            .register_tool(schema)
            .map_err(|e| SentinelError::Registry(e.to_string()))?;
        info!("Registered tool: {}", schema.name);
        Ok(())
    }

    /// Mark the current step as completed.
    ///
    /// This should be called after successful tool execution.
    pub fn end_step(&mut self, result: &str) -> Result<()> {
        self.monitor.end_step(result)?;
        Ok(())
    }

    /// Get the current gas remaining.
    pub fn gas_remaining(&self) -> u64 {
        self.monitor.gas_remaining()
    }

    /// Reset the state monitor for a new execution context.
    pub fn reset_monitor(&mut self) {
        self.monitor.reset();
    }

    /// Get the registry's Merkle root hash.
    pub fn registry_root(&mut self) -> sentinel_registry::Hash {
        self.registry.get_root()
    }

    /// Check if monitor is halted due to security violation.
    pub fn is_halted(&self) -> bool {
        self.monitor.is_halted()
    }

    /// Get the step count.
    pub fn step_count(&self) -> u64 {
        self.monitor.step_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(temp_dir: &TempDir) -> SentinelConfig {
        let mut config = SentinelConfig::default();
        config.registry.db_path = temp_dir.path().join("test_registry.db");
        config.registry.allow_unknown_tools = true; // For testing
        config
    }

    fn test_schema() -> ToolSchema {
        ToolSchema {
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "input": { "type": "string" }
                }
            }),
            output_schema: serde_json::json!({
                "type": "string"
            }),
        }
    }

    #[test]
    fn test_sentinel_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);
        let sentinel = Sentinel::new(config);
        assert!(sentinel.is_ok());
    }

    #[test]
    fn test_register_and_verify() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);
        let mut sentinel = Sentinel::new(config).unwrap();

        let schema = test_schema();
        sentinel.register_tool(&schema).unwrap();

        // Verify passes for registered tool
        let params = serde_json::json!({ "input": "test" });
        let verdict = sentinel
            .analyze_tool_call("test_tool", &schema, &params)
            .unwrap();

        // Should allow (or review for new tool depending on config)
        assert!(!verdict.is_blocked());
    }

    #[test]
    fn test_unknown_tool_blocked() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = test_config(&temp_dir);
        config.registry.allow_unknown_tools = false;

        let mut sentinel = Sentinel::new(config).unwrap();

        let schema = test_schema();
        let params = serde_json::json!({});

        let verdict = sentinel
            .analyze_tool_call("unknown_tool", &schema, &params)
            .unwrap();
        assert!(verdict.is_blocked());
    }

    #[test]
    fn test_gas_tracking() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);
        let sentinel = Sentinel::new(config).unwrap();

        assert!(sentinel.gas_remaining() > 0);
    }

    #[test]
    fn test_step_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);
        let mut sentinel = Sentinel::new(config).unwrap();

        let schema = test_schema();
        sentinel.register_tool(&schema).unwrap();

        let params = serde_json::json!({});

        // First call should work
        let verdict = sentinel
            .analyze_tool_call("test_tool", &schema, &params)
            .unwrap();
        assert!(!verdict.is_blocked());

        // End the step
        sentinel.end_step("success").unwrap();
        assert_eq!(sentinel.step_count(), 1);
    }
}
