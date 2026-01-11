//! Unit tests for sentinel-core.

#[test]
fn test_crate_structure() {
    // Smoke test - verifies the module structure compiles
    use crate::{Sentinel, SentinelConfig, Verdict, BlockReason, ReviewFlag};

    let _config = SentinelConfig::default();
    let _verdict = Verdict::allow();
    let _block = BlockReason::GasExhausted { used: 100, limit: 50 };
    let _flag = ReviewFlag::HighGasUsage { percentage: 90 };
}
