//! # Cycle Detection
//!
//! Detects and prevents infinite loops in MCP agent execution paths.
//!
//! This module implements two complementary cycle detection algorithms:
//! - **Floyd's tortoise-and-hare**: O(n) detection of simple cycles
//! - **Tarjan's SCC algorithm**: O(V+E) detection of complex/nested cycles
//!
//! ## Threat Model
//!
//! MCP agents execute sequences of operations that can form cycles:
//! - **Infinite loops**: Agent enters repeating state sequence, never terminating
//! - **Resource exhaustion**: Unbounded loops consume memory/CPU
//! - **Undetected compromise**: Malicious input crafts cycles to bypass security
//!
//! ## Detection Strategy
//!
//! 1. Each agent step produces an [`ExecutionNode`] representing current state
//! 2. Nodes are tracked in execution path
//! 3. Floyd's algorithm detects simple A→B→A cycles in O(n) time
//! 4. Tarjan's algorithm detects complex strongly connected components
//! 5. On cycle detection, execution halts before damage occurs
//!
//! ## References
//!
//! - Floyd, R. W. (1967). "Nondeterministic Algorithms"
//!   *Journal of the ACM*, 14(4), 636-644.
//! - Tarjan, R. E. (1972). "Depth-first search and linear graph algorithms"
//!   *SIAM Journal on Computing*, 1(2), 146-160.
//!
//! ## Example
//!
//! ```rust
//! use sentinel_monitor::{CycleDetector, ExecutionNode};
//!
//! let mut detector = CycleDetector::new();
//!
//! // Simulate agent execution steps
//! detector.record_step(ExecutionNode::new("state_a", 1));
//! detector.record_step(ExecutionNode::new("state_b", 2));
//! detector.record_step(ExecutionNode::new("state_a", 3)); // Potential cycle!
//!
//! if let Some(cycle) = detector.detect_cycle() {
//!     eprintln!("Cycle detected: {:?}", cycle);
//!     // Halt execution immediately
//! }
//! ```
//!
//! ## Security Notes
//!
//! - Cycle detection MUST be called before each agent step
//! - Detection is conservative: false positives preferred over missed cycles
//! - All detected cycles are logged for forensic analysis

mod cycle;
mod error;
mod gas;

pub use cycle::{Cycle, CycleDetector, ExecutionNode};
pub use error::{MonitorError, Result};
pub use gas::{GasBudget, OperationType};
