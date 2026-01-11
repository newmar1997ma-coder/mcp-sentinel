//! # MCP Sentinel Core
//!
//! Unified security facade for the Model Context Protocol.
//! Orchestrates Registry Guard, State Monitor, and Cognitive Council.
//!
//! ## Threat Coverage
//!
//! MCP Sentinel provides layered defense against multiple attack vectors:
//!
//! | Layer | Component | Threats Blocked |
//! |-------|-----------|-----------------|
//! | Schema | Registry Guard | Rug pulls, shadow servers, schema drift |
//! | State | State Monitor | Infinite loops, gas exhaustion, context flood |
//! | Alignment | Cognitive Council | Single-model compromise, Waluigi Effect |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    MCP SENTINEL CORE                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │                    ┌─────────────────┐                          │
//! │                    │    Sentinel     │  ← Unified Facade        │
//! │                    │      Core       │                          │
//! │                    └────────┬────────┘                          │
//! │                             │                                   │
//! │         ┌───────────────────┼───────────────────┐               │
//! │         ▼                   ▼                   ▼               │
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
//! │  │  Registry   │    │    State    │    │  Cognitive  │          │
//! │  │   Guard     │    │   Monitor   │    │   Council   │          │
//! │  └─────────────┘    └─────────────┘    └─────────────┘          │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use sentinel_core::{Sentinel, SentinelConfig, Verdict};
//!
//! // Initialize with configuration
//! let config = SentinelConfig::default();
//! let sentinel = Sentinel::new(config)?;
//!
//! // Analyze an MCP message
//! let result = sentinel.analyze(&mcp_message).await?;
//! match result {
//!     Verdict::Allow => forward(message),
//!     Verdict::Block { reason } => reject(reason),
//!     Verdict::Review { flags } => escalate(flags),
//! }
//! ```
//!
//! ## Security Notes
//!
//! - All checks execute in order: Registry → Monitor → Council
//! - Any component can veto (short-circuit to Block)
//! - The pipeline is fail-closed: errors result in Block, not Allow
//! - Verdicts include full reasoning for audit trails
//!
//! ## References
//!
//! - MCP Specification: <https://modelcontextprotocol.io/>
//! - Registry Guard: Schema integrity via Merkle trees
//! - State Monitor: Floyd/Tarjan cycles + gas budgeting
//! - Cognitive Council: Byzantine consensus + Waluigi detection

mod config;
mod error;
mod sentinel;
mod verdict;

pub use config::SentinelConfig;
pub use error::SentinelError;
pub use sentinel::Sentinel;
pub use verdict::{BlockReason, ReviewFlag, Verdict};

// Re-export component types for convenience
pub use sentinel_council::{ActionProposal, CognitiveCouncil, CouncilVerdict};
pub use sentinel_monitor::{MonitorStatus, OperationType, StateMonitor, StateMonitorConfig};
pub use sentinel_registry::{DriftLevel, RegistryGuard, ToolSchema, VerifyResult};

/// Core result type for sentinel operations.
pub type Result<T> = std::result::Result<T, SentinelError>;

#[cfg(test)]
mod tests;
