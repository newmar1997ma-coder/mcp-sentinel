//! MCP Sentinel Firewall - Semantic security layer
//!
//! First line of defense: detects prompt injection, sanitizes content,
//! and implements canary token leak detection.

pub mod models;
pub mod perplexity;
pub mod canary;
pub mod cdr;
pub mod firewall;

pub use firewall::SemanticFirewall;
pub use models::{ScanResult, ThreatType, SanitizeError};
