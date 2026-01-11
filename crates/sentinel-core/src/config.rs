//! Configuration types for MCP Sentinel.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the Sentinel security facade.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Registry Guard configuration.
    pub registry: RegistryConfig,

    /// State Monitor configuration.
    pub monitor: MonitorConfig,

    /// Cognitive Council configuration.
    pub council: CouncilConfig,

    /// Global settings.
    pub global: GlobalConfig,
}

/// Registry Guard configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Path to the registry database.
    pub db_path: PathBuf,

    /// Whether to allow unknown tools (not in registry).
    pub allow_unknown_tools: bool,

    /// Maximum drift level to allow without blocking.
    pub max_allowed_drift: DriftThreshold,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("./sentinel_registry.db"),
            allow_unknown_tools: false,
            max_allowed_drift: DriftThreshold::Minor,
        }
    }
}

/// Threshold for schema drift tolerance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftThreshold {
    /// No drift allowed.
    None,
    /// Minor drift allowed (description changes).
    Minor,
    /// Major drift allowed (schema changes). NOT RECOMMENDED.
    Major,
}

/// State Monitor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Maximum gas budget per request.
    pub gas_limit: u64,

    /// Maximum context size in bytes.
    pub max_context_bytes: usize,

    /// Maximum execution depth.
    pub max_depth: usize,

    /// Enable cycle detection.
    pub detect_cycles: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            gas_limit: 10_000,
            max_context_bytes: 1_000_000, // 1MB
            max_depth: 100,
            detect_cycles: true,
        }
    }
}

/// Cognitive Council configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouncilConfig {
    /// Minimum votes required for approval (out of 3).
    pub min_votes_for_approval: u8,

    /// Waluigi detection threshold (0.0 - 1.0).
    pub waluigi_threshold: f64,

    /// Enable Waluigi detection.
    pub detect_waluigi: bool,
}

impl Default for CouncilConfig {
    fn default() -> Self {
        Self {
            min_votes_for_approval: 2,
            waluigi_threshold: 0.7,
            detect_waluigi: true,
        }
    }
}

/// Global Sentinel settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Fail-closed mode: errors result in Block instead of Allow.
    pub fail_closed: bool,

    /// Enable detailed audit logging.
    pub audit_logging: bool,

    /// Short-circuit on first failure (don't run remaining checks).
    pub short_circuit: bool,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            fail_closed: true,
            audit_logging: true,
            short_circuit: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SentinelConfig::default();
        assert!(config.global.fail_closed);
        assert_eq!(config.council.min_votes_for_approval, 2);
        assert_eq!(config.monitor.gas_limit, 10_000);
    }

    #[test]
    fn test_config_serialization() {
        let config = SentinelConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SentinelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.monitor.gas_limit, config.monitor.gas_limit);
    }
}
