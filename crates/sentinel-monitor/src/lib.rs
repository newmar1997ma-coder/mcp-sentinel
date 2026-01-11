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
//! ## Components
//!
//! | Component | Purpose |
//! |-----------|---------|
//! | [`StateMonitor`] | Unified facade integrating all protections |
//! | [`CycleDetector`] | Floyd + Tarjan cycle detection |
//! | [`GasBudget`] | Computational resource limits |
//! | [`ContextManager`] | LRU-based memory management |
//!
//! ## Quick Start
//!
//! ```rust
//! use sentinel_monitor::{StateMonitor, OperationType};
//!
//! let mut monitor = StateMonitor::new();
//!
//! // Before each agent operation:
//! monitor.begin_step("read_file", OperationType::ToolCall)?;
//!
//! // ... execute the operation ...
//!
//! // After successful operation:
//! monitor.end_step("file contents")?;
//!
//! // Check status
//! assert!(monitor.gas_remaining() > 0);
//! # Ok::<(), sentinel_monitor::MonitorError>(())
//! ```
//!
//! ## References
//!
//! - Floyd, R. W. (1967). "Nondeterministic Algorithms"
//!   *Journal of the ACM*, 14(4), 636-644.
//! - Tarjan, R. E. (1972). "Depth-first search and linear graph algorithms"
//!   *SIAM Journal on Computing*, 1(2), 146-160.
//! - Ethereum Yellow Paper, Section 9: Execution Model (gas semantics)
//!
//! ## Security Notes
//!
//! - All checks execute BEFORE the guarded operation
//! - Any failed check MUST halt execution immediately
//! - Monitoring state is append-only during execution
//! - Reset operations are privileged (new execution context only)

mod cycle;
mod error;
mod flush;
mod gas;
mod monitor;

pub use cycle::{Cycle, CycleDetector, ExecutionNode};
pub use error::{MonitorError, Result};
pub use flush::{ContextManager, Frame};
pub use gas::{GasBudget, OperationType};
pub use monitor::{MonitorStatus, StateMonitor, StateMonitorConfig};
