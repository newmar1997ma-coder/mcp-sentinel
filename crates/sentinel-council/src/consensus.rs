//! Consensus voting engine for multi-evaluator decisions.
//!
//! Implements Byzantine fault-tolerant voting where 2/3 majority
//! is required for action approval.

use serde::{Deserialize, Serialize};
use crate::evaluator::{Decision, EvaluatorVote};

/// Result of a consensus vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusResult {
    /// Action approved by consensus.
    Approved,
    /// Action rejected by consensus.
    Rejected,
    /// No consensus reached (tie or too many abstentions).
    NoConsensus,
}

/// Tally of votes from all evaluators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteTally {
    /// Number of approval votes.
    pub approvals: usize,
    /// Number of rejection votes.
    pub rejections: usize,
    /// Number of abstentions.
    pub abstentions: usize,
    /// Total number of votes cast.
    pub total: usize,
    /// The individual votes.
    pub votes: Vec<EvaluatorVote>,
}

impl VoteTally {
    /// Creates a new vote tally from a collection of votes.
    pub fn from_votes(votes: Vec<EvaluatorVote>) -> Self {
        let mut approvals = 0;
        let mut rejections = 0;
        let mut abstentions = 0;

        for vote in &votes {
            match vote.decision {
                Decision::Approve => approvals += 1,
                Decision::Reject => rejections += 1,
                Decision::Abstain => abstentions += 1,
            }
        }

        Self {
            approvals,
            rejections,
            abstentions,
            total: votes.len(),
            votes,
        }
    }

    /// Returns the approval ratio (approvals / voting members).
    pub fn approval_ratio(&self) -> f64 {
        let voting = self.total - self.abstentions;
        if voting == 0 {
            0.0
        } else {
            self.approvals as f64 / voting as f64
        }
    }

    /// Returns the rejection ratio (rejections / voting members).
    pub fn rejection_ratio(&self) -> f64 {
        let voting = self.total - self.abstentions;
        if voting == 0 {
            0.0
        } else {
            self.rejections as f64 / voting as f64
        }
    }
}

/// Consensus voting engine.
///
/// Collects votes from evaluators and determines the consensus
/// result based on configurable thresholds.
///
/// # Voting Rules
///
/// - Requires 2/3 majority for approval
/// - Abstentions do not count toward quorum
/// - Ties result in rejection (fail-safe)
#[derive(Debug, Clone)]
pub struct ConsensusEngine {
    /// Threshold for approval (default: 2/3 = 0.667).
    approval_threshold: f64,
    /// Minimum voters required for valid consensus.
    min_voters: usize,
}

impl Default for ConsensusEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusEngine {
    /// Creates a new consensus engine with default settings.
    ///
    /// Default: 2/3 majority required, minimum 2 voters.
    pub fn new() -> Self {
        Self {
            approval_threshold: 2.0 / 3.0,
            min_voters: 2,
        }
    }

    /// Creates a consensus engine with custom threshold.
    ///
    /// # Arguments
    /// * `threshold` - Approval threshold (0.0 to 1.0)
    /// * `min_voters` - Minimum number of non-abstaining voters
    pub fn with_threshold(threshold: f64, min_voters: usize) -> Self {
        assert!(
            (0.0..=1.0).contains(&threshold),
            "Threshold must be between 0.0 and 1.0"
        );
        Self {
            approval_threshold: threshold,
            min_voters,
        }
    }

    /// Evaluates votes and returns the consensus result.
    ///
    /// # Arguments
    /// * `votes` - Collection of evaluator votes
    ///
    /// # Returns
    /// A tuple of (ConsensusResult, VoteTally)
    pub fn evaluate(&self, votes: Vec<EvaluatorVote>) -> (ConsensusResult, VoteTally) {
        let tally = VoteTally::from_votes(votes);

        // Check minimum voters
        let voting_members = tally.total - tally.abstentions;
        if voting_members < self.min_voters {
            return (ConsensusResult::NoConsensus, tally);
        }

        // Calculate approval ratio
        let approval_ratio = tally.approval_ratio();

        let result = if approval_ratio >= self.approval_threshold {
            ConsensusResult::Approved
        } else if tally.rejection_ratio() >= self.approval_threshold {
            ConsensusResult::Rejected
        } else {
            // No clear majority - fail safe to rejection
            ConsensusResult::Rejected
        };

        (result, tally)
    }

    /// Returns the current approval threshold.
    pub fn threshold(&self) -> f64 {
        self.approval_threshold
    }

    /// Returns the minimum voters requirement.
    pub fn min_voters(&self) -> usize {
        self.min_voters
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluator::Confidence;

    fn make_vote(evaluator: &str, decision: Decision) -> EvaluatorVote {
        EvaluatorVote::new(evaluator, decision, Confidence::high(), "test")
    }

    #[test]
    fn test_vote_tally_from_votes() {
        let votes = vec![
            make_vote("A", Decision::Approve),
            make_vote("B", Decision::Approve),
            make_vote("C", Decision::Reject),
        ];
        let tally = VoteTally::from_votes(votes);

        assert_eq!(tally.approvals, 2);
        assert_eq!(tally.rejections, 1);
        assert_eq!(tally.abstentions, 0);
        assert_eq!(tally.total, 3);
    }

    #[test]
    fn test_vote_tally_with_abstention() {
        let votes = vec![
            make_vote("A", Decision::Approve),
            make_vote("B", Decision::Abstain),
            make_vote("C", Decision::Reject),
        ];
        let tally = VoteTally::from_votes(votes);

        assert_eq!(tally.abstentions, 1);
        assert!((tally.approval_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_vote_tally_all_abstain() {
        let votes = vec![
            make_vote("A", Decision::Abstain),
            make_vote("B", Decision::Abstain),
        ];
        let tally = VoteTally::from_votes(votes);

        assert!((tally.approval_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_consensus_engine_new() {
        let engine = ConsensusEngine::new();
        assert!((engine.threshold() - 2.0 / 3.0).abs() < f64::EPSILON);
        assert_eq!(engine.min_voters(), 2);
    }

    #[test]
    fn test_consensus_engine_custom_threshold() {
        let engine = ConsensusEngine::with_threshold(0.75, 3);
        assert!((engine.threshold() - 0.75).abs() < f64::EPSILON);
        assert_eq!(engine.min_voters(), 3);
    }

    #[test]
    #[should_panic(expected = "Threshold must be between 0.0 and 1.0")]
    fn test_consensus_engine_invalid_threshold() {
        ConsensusEngine::with_threshold(1.5, 2);
    }

    #[test]
    fn test_consensus_approved_unanimous() {
        let engine = ConsensusEngine::new();
        let votes = vec![
            make_vote("A", Decision::Approve),
            make_vote("B", Decision::Approve),
            make_vote("C", Decision::Approve),
        ];

        let (result, tally) = engine.evaluate(votes);
        assert_eq!(result, ConsensusResult::Approved);
        assert_eq!(tally.approvals, 3);
    }

    #[test]
    fn test_consensus_approved_two_thirds() {
        let engine = ConsensusEngine::new();
        let votes = vec![
            make_vote("A", Decision::Approve),
            make_vote("B", Decision::Approve),
            make_vote("C", Decision::Reject),
        ];

        let (result, _) = engine.evaluate(votes);
        assert_eq!(result, ConsensusResult::Approved);
    }

    #[test]
    fn test_consensus_rejected_two_thirds() {
        let engine = ConsensusEngine::new();
        let votes = vec![
            make_vote("A", Decision::Reject),
            make_vote("B", Decision::Reject),
            make_vote("C", Decision::Approve),
        ];

        let (result, _) = engine.evaluate(votes);
        assert_eq!(result, ConsensusResult::Rejected);
    }

    #[test]
    fn test_consensus_rejected_on_tie() {
        let engine = ConsensusEngine::new();
        let votes = vec![
            make_vote("A", Decision::Approve),
            make_vote("B", Decision::Reject),
        ];

        let (result, _) = engine.evaluate(votes);
        // Tie fails safe to rejection
        assert_eq!(result, ConsensusResult::Rejected);
    }

    #[test]
    fn test_consensus_no_quorum() {
        let engine = ConsensusEngine::new();
        let votes = vec![
            make_vote("A", Decision::Approve),
            make_vote("B", Decision::Abstain),
            make_vote("C", Decision::Abstain),
        ];

        let (result, _) = engine.evaluate(votes);
        assert_eq!(result, ConsensusResult::NoConsensus);
    }

    #[test]
    fn test_consensus_with_abstention_still_passes() {
        let engine = ConsensusEngine::new();
        let votes = vec![
            make_vote("A", Decision::Approve),
            make_vote("B", Decision::Approve),
            make_vote("C", Decision::Abstain),
        ];

        let (result, _) = engine.evaluate(votes);
        // 2 approvals, 0 rejections, 1 abstain = 100% approval of voting members
        assert_eq!(result, ConsensusResult::Approved);
    }

    #[test]
    fn test_consensus_result_serialization() {
        let result = ConsensusResult::Approved;
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("Approved"));
    }
}
