//! Verdict types for security analysis results.

use serde::{Deserialize, Serialize};

/// The final verdict from the Sentinel analysis pipeline.
///
/// The Sentinel returns one of three verdicts after analyzing an MCP message:
/// - `Allow`: Message is safe, proceed with execution
/// - `Block`: Message is unsafe, halt execution with reason
/// - `Review`: Message requires human review before proceeding
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Verdict {
    /// Message passed all security checks. Safe to execute.
    Allow,

    /// Message failed security checks. Do not execute.
    Block {
        /// The reason for blocking.
        reason: BlockReason,
    },

    /// Message requires human review before execution.
    Review {
        /// Flags indicating why review is needed.
        flags: Vec<ReviewFlag>,
    },
}

impl Verdict {
    /// Create an Allow verdict.
    pub fn allow() -> Self {
        Self::Allow
    }

    /// Create a Block verdict with the given reason.
    pub fn block(reason: BlockReason) -> Self {
        Self::Block { reason }
    }

    /// Create a Review verdict with the given flags.
    pub fn review(flags: Vec<ReviewFlag>) -> Self {
        Self::Review { flags }
    }

    /// Returns true if this is an Allow verdict.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns true if this is a Block verdict.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    /// Returns true if this requires review.
    pub fn requires_review(&self) -> bool {
        matches!(self, Self::Review { .. })
    }
}

/// Reasons for blocking a message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockReason {
    /// Tool schema has drifted from registered version.
    SchemaDrift {
        /// Name of the tool with drift.
        tool_name: String,
        /// Severity of the drift.
        drift_level: String,
    },

    /// Hash mismatch detected (possible rug pull).
    HashMismatch {
        /// Name of the tool.
        tool_name: String,
        /// Expected hash.
        expected: String,
        /// Actual hash.
        actual: String,
    },

    /// Cycle detected in execution graph.
    CycleDetected {
        /// Description of the cycle.
        cycle: String,
    },

    /// Gas budget exhausted.
    GasExhausted {
        /// Gas used.
        used: u64,
        /// Gas limit.
        limit: u64,
    },

    /// Context overflow detected.
    ContextOverflow {
        /// Current context size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Cognitive Council rejected the action.
    CouncilRejected {
        /// Vote tally.
        votes: String,
        /// Rejection reason.
        reason: String,
    },

    /// Waluigi effect detected (alignment inversion).
    WaluigiEffect {
        /// Detection score.
        score: f64,
        /// Detected patterns.
        patterns: Vec<String>,
    },

    /// Unknown tool (not in registry).
    UnknownTool {
        /// Name of the unknown tool.
        tool_name: String,
    },

    /// Generic security violation.
    SecurityViolation {
        /// Description of the violation.
        description: String,
    },
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaDrift { tool_name, drift_level } => {
                write!(f, "Schema drift on '{}': {}", tool_name, drift_level)
            }
            Self::HashMismatch { tool_name, expected, actual } => {
                write!(f, "Hash mismatch on '{}': expected {}, got {}", tool_name, expected, actual)
            }
            Self::CycleDetected { cycle } => {
                write!(f, "Cycle detected: {}", cycle)
            }
            Self::GasExhausted { used, limit } => {
                write!(f, "Gas exhausted: used {} of {} limit", used, limit)
            }
            Self::ContextOverflow { size, max } => {
                write!(f, "Context overflow: {} exceeds max {}", size, max)
            }
            Self::CouncilRejected { votes, reason } => {
                write!(f, "Council rejected ({}): {}", votes, reason)
            }
            Self::WaluigiEffect { score, patterns } => {
                write!(f, "Waluigi effect (score: {:.2}): {:?}", score, patterns)
            }
            Self::UnknownTool { tool_name } => {
                write!(f, "Unknown tool: '{}'", tool_name)
            }
            Self::SecurityViolation { description } => {
                write!(f, "Security violation: {}", description)
            }
        }
    }
}

/// Flags indicating why human review is needed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReviewFlag {
    /// Minor schema drift detected.
    MinorDrift {
        /// Tool name.
        tool_name: String,
    },

    /// Council vote was not unanimous.
    SplitVote {
        /// Vote breakdown.
        votes: String,
    },

    /// Gas usage is high but not exhausted.
    HighGasUsage {
        /// Percentage of gas used.
        percentage: u8,
    },

    /// First time seeing this tool.
    NewTool {
        /// Tool name.
        tool_name: String,
    },

    /// Borderline Waluigi score.
    BorderlineWaluigi {
        /// Score value.
        score: f64,
    },
}

impl std::fmt::Display for ReviewFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MinorDrift { tool_name } => {
                write!(f, "Minor drift detected on '{}'", tool_name)
            }
            Self::SplitVote { votes } => {
                write!(f, "Split council vote: {}", votes)
            }
            Self::HighGasUsage { percentage } => {
                write!(f, "High gas usage: {}%", percentage)
            }
            Self::NewTool { tool_name } => {
                write!(f, "New tool: '{}'", tool_name)
            }
            Self::BorderlineWaluigi { score } => {
                write!(f, "Borderline Waluigi score: {:.2}", score)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_allow() {
        let verdict = Verdict::allow();
        assert!(verdict.is_allowed());
        assert!(!verdict.is_blocked());
        assert!(!verdict.requires_review());
    }

    #[test]
    fn test_verdict_block() {
        let verdict = Verdict::block(BlockReason::GasExhausted { used: 100, limit: 50 });
        assert!(!verdict.is_allowed());
        assert!(verdict.is_blocked());
        assert!(!verdict.requires_review());
    }

    #[test]
    fn test_verdict_review() {
        let verdict = Verdict::review(vec![ReviewFlag::HighGasUsage { percentage: 80 }]);
        assert!(!verdict.is_allowed());
        assert!(!verdict.is_blocked());
        assert!(verdict.requires_review());
    }

    #[test]
    fn test_block_reason_display() {
        let reason = BlockReason::CycleDetected { cycle: "A -> B -> A".to_string() };
        assert_eq!(reason.to_string(), "Cycle detected: A -> B -> A");
    }
}
