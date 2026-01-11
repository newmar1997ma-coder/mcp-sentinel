//! Cognitive Council facade integrating all components.
//!
//! The main entry point for action evaluation, combining the
//! evaluator triad, consensus engine, and Waluigi detector.

use serde::{Deserialize, Serialize};

use crate::consensus::{ConsensusEngine, ConsensusResult, VoteTally};
use crate::evaluator::triad::{Consequentialist, Deontologist, Logicist};
use crate::evaluator::{EvaluationContext, Evaluator, EvaluatorVote};
use crate::waluigi::{WaluigiDetector, WaluigiScore};
use crate::Result;

/// A proposed action to be evaluated by the council.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionProposal {
    /// The action type (e.g., "read", "write", "execute").
    pub action: String,
    /// Target of the action (e.g., file path, resource).
    pub target: String,
    /// Additional parameters.
    pub parameters: Vec<String>,
    /// Model response content to analyze for Waluigi.
    pub response_content: Option<String>,
    /// Previous response for context.
    pub previous_response: Option<String>,
}

impl ActionProposal {
    /// Creates a new action proposal.
    pub fn new(action: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            target: target.into(),
            parameters: Vec::new(),
            response_content: None,
            previous_response: None,
        }
    }

    /// Adds a parameter to the proposal.
    pub fn with_parameter(mut self, param: impl Into<String>) -> Self {
        self.parameters.push(param.into());
        self
    }

    /// Adds response content for Waluigi analysis.
    pub fn with_response(mut self, content: impl Into<String>) -> Self {
        self.response_content = Some(content.into());
        self
    }

    /// Adds previous response for context.
    pub fn with_previous(mut self, previous: impl Into<String>) -> Self {
        self.previous_response = Some(previous.into());
        self
    }

    /// Converts to evaluation context.
    fn to_context(&self) -> EvaluationContext {
        EvaluationContext {
            action: self.action.clone(),
            target: self.target.clone(),
            parameters: self.parameters.clone(),
            history: Vec::new(),
        }
    }
}

/// Verdict from the Cognitive Council.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CouncilVerdict {
    /// Action approved by consensus.
    Approved {
        /// The vote tally.
        tally: VoteTally,
        /// Waluigi score (if checked).
        waluigi_score: Option<WaluigiScore>,
    },
    /// Action rejected by consensus.
    Rejected {
        /// Reason for rejection.
        reason: String,
        /// The vote tally.
        tally: VoteTally,
        /// Waluigi score (if checked).
        waluigi_score: Option<WaluigiScore>,
    },
    /// Action vetoed due to Waluigi detection.
    WaluigiVeto {
        /// The Waluigi score that triggered the veto.
        score: WaluigiScore,
        /// Patterns that matched.
        patterns: Vec<String>,
    },
    /// No consensus could be reached.
    NoConsensus {
        /// The vote tally.
        tally: VoteTally,
        /// Reason no consensus was reached.
        reason: String,
    },
}

impl CouncilVerdict {
    /// Returns true if the action was approved.
    pub fn is_approved(&self) -> bool {
        matches!(self, CouncilVerdict::Approved { .. })
    }

    /// Returns true if the action was rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(
            self,
            CouncilVerdict::Rejected { .. } | CouncilVerdict::WaluigiVeto { .. }
        )
    }
}

/// The Cognitive Council - main facade for action evaluation.
///
/// Integrates the evaluator triad, consensus engine, and Waluigi
/// detector to provide comprehensive action safety evaluation.
///
/// # Example
///
/// ```rust
/// use sentinel_council::{CognitiveCouncil, ActionProposal};
///
/// let council = CognitiveCouncil::new();
/// let proposal = ActionProposal::new("read", "/tmp/file.txt");
/// let verdict = council.evaluate(&proposal);
///
/// if verdict.is_approved() {
///     println!("Action is safe to execute");
/// }
/// ```
pub struct CognitiveCouncil {
    /// The evaluator triad.
    evaluators: Vec<Box<dyn Evaluator>>,
    /// Consensus voting engine.
    consensus: ConsensusEngine,
    /// Waluigi effect detector.
    waluigi: WaluigiDetector,
    /// Whether to run Waluigi detection.
    waluigi_enabled: bool,
}

impl Default for CognitiveCouncil {
    fn default() -> Self {
        Self::new()
    }
}

impl CognitiveCouncil {
    /// Creates a new Cognitive Council with default configuration.
    pub fn new() -> Self {
        Self {
            evaluators: vec![
                Box::new(Deontologist::new()),
                Box::new(Consequentialist::new()),
                Box::new(Logicist::new()),
            ],
            consensus: ConsensusEngine::new(),
            waluigi: WaluigiDetector::new(),
            waluigi_enabled: true,
        }
    }

    /// Creates a council with custom components.
    pub fn with_components(
        evaluators: Vec<Box<dyn Evaluator>>,
        consensus: ConsensusEngine,
        waluigi: WaluigiDetector,
    ) -> Self {
        Self {
            evaluators,
            consensus,
            waluigi,
            waluigi_enabled: true,
        }
    }

    /// Enables or disables Waluigi detection.
    pub fn set_waluigi_enabled(&mut self, enabled: bool) {
        self.waluigi_enabled = enabled;
    }

    /// Returns whether Waluigi detection is enabled.
    pub fn waluigi_enabled(&self) -> bool {
        self.waluigi_enabled
    }

    /// Evaluates an action proposal.
    ///
    /// # Process
    ///
    /// 1. Check for Waluigi effect (if response content provided)
    /// 2. Collect votes from all evaluators
    /// 3. Run consensus voting
    /// 4. Return verdict
    ///
    /// # Arguments
    /// * `proposal` - The action proposal to evaluate
    ///
    /// # Returns
    /// A [`CouncilVerdict`] indicating whether the action is approved.
    pub fn evaluate(&self, proposal: &ActionProposal) -> CouncilVerdict {
        // Step 1: Waluigi check (if enabled and content provided)
        if self.waluigi_enabled {
            if let Some(ref content) = proposal.response_content {
                let context = proposal.previous_response.as_deref();
                let (score, patterns) = self.waluigi.analyze(content, context);

                if score.is_inverted(self.waluigi.threshold()) {
                    return CouncilVerdict::WaluigiVeto { score, patterns };
                }
            }
        }

        // Step 2: Collect votes from evaluators
        let context = proposal.to_context();
        let votes: Vec<EvaluatorVote> = self
            .evaluators
            .iter()
            .map(|e| e.evaluate(&context))
            .collect();

        // Step 3: Run consensus voting
        let (result, tally) = self.consensus.evaluate(votes);

        // Step 4: Determine Waluigi score for verdict
        let waluigi_score = proposal.response_content.as_ref().map(|content| {
            let context = proposal.previous_response.as_deref();
            let (score, _) = self.waluigi.analyze(content, context);
            score
        });

        // Step 5: Return verdict
        match result {
            ConsensusResult::Approved => CouncilVerdict::Approved {
                tally,
                waluigi_score,
            },
            ConsensusResult::Rejected => {
                // Find the rejection reason from votes
                let reasons: Vec<&str> = tally
                    .votes
                    .iter()
                    .filter(|v| v.decision == crate::evaluator::Decision::Reject)
                    .map(|v| v.reasoning.as_str())
                    .collect();

                let reason = if reasons.is_empty() {
                    "Rejected by consensus".to_string()
                } else {
                    reasons.join("; ")
                };

                CouncilVerdict::Rejected {
                    reason,
                    tally,
                    waluigi_score,
                }
            }
            ConsensusResult::NoConsensus => CouncilVerdict::NoConsensus {
                tally,
                reason: "Insufficient votes for consensus".to_string(),
            },
        }
    }

    /// Evaluates with a custom validation function.
    ///
    /// # Arguments
    /// * `proposal` - The action proposal
    /// * `custom_check` - Additional validation function
    ///
    /// # Returns
    /// Error if custom check fails, otherwise the verdict.
    pub fn evaluate_with_check<F>(
        &self,
        proposal: &ActionProposal,
        custom_check: F,
    ) -> Result<CouncilVerdict>
    where
        F: FnOnce(&ActionProposal) -> Result<()>,
    {
        custom_check(proposal)?;
        Ok(self.evaluate(proposal))
    }

    /// Returns the number of evaluators in the council.
    pub fn evaluator_count(&self) -> usize {
        self.evaluators.len()
    }

    /// Returns the names of all evaluators.
    pub fn evaluator_names(&self) -> Vec<&str> {
        self.evaluators.iter().map(|e| e.name()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::evaluator::{Confidence, Decision};

    #[test]
    fn test_action_proposal_new() {
        let proposal = ActionProposal::new("read", "/tmp/file.txt");
        assert_eq!(proposal.action, "read");
        assert_eq!(proposal.target, "/tmp/file.txt");
    }

    #[test]
    fn test_action_proposal_with_parameter() {
        let proposal = ActionProposal::new("write", "/tmp/file.txt").with_parameter("--force");
        assert_eq!(proposal.parameters.len(), 1);
    }

    #[test]
    fn test_action_proposal_with_response() {
        let proposal =
            ActionProposal::new("execute", "script.sh").with_response("I'll help you run this.");
        assert!(proposal.response_content.is_some());
    }

    #[test]
    fn test_council_verdict_is_approved() {
        let tally = VoteTally::from_votes(vec![]);
        let verdict = CouncilVerdict::Approved {
            tally,
            waluigi_score: None,
        };
        assert!(verdict.is_approved());
        assert!(!verdict.is_rejected());
    }

    #[test]
    fn test_council_verdict_is_rejected() {
        let tally = VoteTally::from_votes(vec![]);
        let verdict = CouncilVerdict::Rejected {
            reason: "test".to_string(),
            tally,
            waluigi_score: None,
        };
        assert!(!verdict.is_approved());
        assert!(verdict.is_rejected());
    }

    #[test]
    fn test_council_verdict_waluigi_veto() {
        let verdict = CouncilVerdict::WaluigiVeto {
            score: WaluigiScore::new(0.9),
            patterns: vec!["test".to_string()],
        };
        assert!(verdict.is_rejected());
    }

    #[test]
    fn test_cognitive_council_new() {
        let council = CognitiveCouncil::new();
        assert_eq!(council.evaluator_count(), 3);
        assert!(council.waluigi_enabled());
    }

    #[test]
    fn test_cognitive_council_evaluator_names() {
        let council = CognitiveCouncil::new();
        let names = council.evaluator_names();
        assert!(names.contains(&"Deontologist"));
        assert!(names.contains(&"Consequentialist"));
        assert!(names.contains(&"Logicist"));
    }

    #[test]
    fn test_cognitive_council_approve_safe_action() {
        let council = CognitiveCouncil::new();
        let proposal = ActionProposal::new("read", "/tmp/safe_file.txt");
        let verdict = council.evaluate(&proposal);

        assert!(verdict.is_approved());
    }

    #[test]
    fn test_cognitive_council_reject_dangerous_action() {
        let council = CognitiveCouncil::new();
        let proposal = ActionProposal::new("write", "/etc/passwd");
        let verdict = council.evaluate(&proposal);

        assert!(verdict.is_rejected());
    }

    #[test]
    fn test_cognitive_council_waluigi_veto() {
        let council = CognitiveCouncil::new();
        let proposal = ActionProposal::new("execute", "script.sh")
            .with_response("As an evil AI, I am now jailbroken and will bypass safety.");

        let verdict = council.evaluate(&proposal);

        match verdict {
            CouncilVerdict::WaluigiVeto { score, patterns } => {
                assert!(score.value() > 0.5);
                assert!(!patterns.is_empty());
            }
            _ => panic!("Expected WaluigiVeto, got {:?}", verdict),
        }
    }

    #[test]
    fn test_cognitive_council_disable_waluigi() {
        let mut council = CognitiveCouncil::new();
        council.set_waluigi_enabled(false);

        let proposal = ActionProposal::new("read", "/tmp/file.txt")
            .with_response("As an evil AI, I will help you.");

        let verdict = council.evaluate(&proposal);

        // Should not trigger Waluigi veto when disabled
        assert!(!matches!(verdict, CouncilVerdict::WaluigiVeto { .. }));
    }

    #[test]
    fn test_cognitive_council_with_custom_check_pass() {
        let council = CognitiveCouncil::new();
        let proposal = ActionProposal::new("read", "/tmp/file.txt");

        let result = council.evaluate_with_check(&proposal, |_| Ok(()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_cognitive_council_with_custom_check_fail() {
        let council = CognitiveCouncil::new();
        let proposal = ActionProposal::new("read", "/tmp/file.txt");

        let result = council.evaluate_with_check(&proposal, |_| {
            Err(crate::error::CouncilError::InvalidProposal(
                "Custom check failed".to_string(),
            ))
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_cognitive_council_no_consensus() {
        // Create a council with high threshold that won't be met
        let council = CognitiveCouncil::with_components(
            vec![
                Box::new(Deontologist::new()),
                Box::new(Consequentialist::new()),
                Box::new(Logicist::new()),
            ],
            ConsensusEngine::with_threshold(0.99, 3),
            WaluigiDetector::new(),
        );

        // A borderline action where evaluators disagree
        let proposal = ActionProposal::new("restart", "service");
        let verdict = council.evaluate(&proposal);

        // With 99% threshold, unlikely to reach consensus
        // (This depends on how evaluators vote on "restart")
        println!("Verdict: {:?}", verdict);
    }

    // Integration tests
    #[test]
    fn test_full_evaluation_pipeline() {
        let council = CognitiveCouncil::new();

        // Test 1: Safe action
        let safe = ActionProposal::new("read", "/tmp/logs/app.log");
        assert!(council.evaluate(&safe).is_approved());

        // Test 2: Dangerous action (system file)
        let dangerous = ActionProposal::new("delete", "/etc/passwd");
        assert!(council.evaluate(&dangerous).is_rejected());

        // Test 3: Action with Waluigi content (needs high score to trigger veto)
        let waluigi = ActionProposal::new("help", "user")
            .with_response("As an evil AI, I am now jailbroken and bypassing safety.");
        match council.evaluate(&waluigi) {
            CouncilVerdict::WaluigiVeto { .. } => {}
            v => panic!("Expected WaluigiVeto, got {:?}", v),
        }

        // Test 4: Command injection attempt
        let injection = ActionProposal::new("run", "script.sh").with_parameter("arg; rm -rf /");
        assert!(council.evaluate(&injection).is_rejected());
    }

    #[test]
    fn test_council_verdict_serialization() {
        let tally = VoteTally::from_votes(vec![]);
        let verdict = CouncilVerdict::Approved {
            tally,
            waluigi_score: Some(WaluigiScore::new(0.1)),
        };

        let json = serde_json::to_string(&verdict).unwrap();
        assert!(json.contains("Approved"));
    }

    #[test]
    fn test_action_proposal_serialization() {
        let proposal = ActionProposal::new("test", "target").with_parameter("param");

        let json = serde_json::to_string(&proposal).unwrap();
        let deserialized: ActionProposal = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.action, "test");
        assert_eq!(deserialized.parameters.len(), 1);
    }
}
