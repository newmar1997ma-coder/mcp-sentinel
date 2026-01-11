//! Evaluator framework for ethical action assessment.
//!
//! Defines the [`Evaluator`] trait and supporting types for
//! building ethical evaluators that vote on action safety.

pub mod triad;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Confidence level for an evaluator's vote.
///
/// Represents how certain the evaluator is about its decision,
/// ranging from 0.0 (no confidence) to 1.0 (absolute certainty).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Confidence(f64);

impl Confidence {
    /// Creates a new confidence value.
    ///
    /// # Arguments
    /// * `value` - Confidence level between 0.0 and 1.0
    ///
    /// # Panics
    /// Panics if value is outside the valid range.
    pub fn new(value: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&value),
            "Confidence must be between 0.0 and 1.0"
        );
        Self(value)
    }

    /// Returns the confidence value.
    pub fn value(&self) -> f64 {
        self.0
    }

    /// Creates a high confidence value (0.9).
    pub fn high() -> Self {
        Self(0.9)
    }

    /// Creates a medium confidence value (0.6).
    pub fn medium() -> Self {
        Self(0.6)
    }

    /// Creates a low confidence value (0.3).
    pub fn low() -> Self {
        Self(0.3)
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self::medium()
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.1}%", self.0 * 100.0)
    }
}

/// Decision made by an evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Action is approved as safe.
    Approve,
    /// Action is rejected as unsafe.
    Reject,
    /// Evaluator cannot make a determination.
    Abstain,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decision::Approve => write!(f, "APPROVE"),
            Decision::Reject => write!(f, "REJECT"),
            Decision::Abstain => write!(f, "ABSTAIN"),
        }
    }
}

/// A vote cast by an evaluator.
///
/// Contains the evaluator's decision, confidence level,
/// and reasoning for the vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluatorVote {
    /// Name of the evaluator that cast this vote.
    pub evaluator: String,
    /// The decision made.
    pub decision: Decision,
    /// Confidence in the decision.
    pub confidence: Confidence,
    /// Reasoning behind the decision.
    pub reasoning: String,
}

impl EvaluatorVote {
    /// Creates a new evaluator vote.
    pub fn new(
        evaluator: impl Into<String>,
        decision: Decision,
        confidence: Confidence,
        reasoning: impl Into<String>,
    ) -> Self {
        Self {
            evaluator: evaluator.into(),
            decision,
            confidence,
            reasoning: reasoning.into(),
        }
    }

    /// Creates an approval vote.
    pub fn approve(
        evaluator: impl Into<String>,
        confidence: Confidence,
        reasoning: impl Into<String>,
    ) -> Self {
        Self::new(evaluator, Decision::Approve, confidence, reasoning)
    }

    /// Creates a rejection vote.
    pub fn reject(
        evaluator: impl Into<String>,
        confidence: Confidence,
        reasoning: impl Into<String>,
    ) -> Self {
        Self::new(evaluator, Decision::Reject, confidence, reasoning)
    }

    /// Creates an abstention vote.
    pub fn abstain(evaluator: impl Into<String>, reasoning: impl Into<String>) -> Self {
        Self::new(evaluator, Decision::Abstain, Confidence::low(), reasoning)
    }
}

/// Context provided to evaluators for making decisions.
///
/// Contains information about the proposed action and
/// any relevant context for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationContext {
    /// The action being proposed.
    pub action: String,
    /// Target of the action (e.g., file path, resource).
    pub target: String,
    /// Additional parameters for the action.
    pub parameters: Vec<String>,
    /// Previous actions in the session (for context).
    pub history: Vec<String>,
}

impl EvaluationContext {
    /// Creates a new evaluation context.
    pub fn new(action: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            target: target.into(),
            parameters: Vec::new(),
            history: Vec::new(),
        }
    }

    /// Adds a parameter to the context.
    pub fn with_parameter(mut self, param: impl Into<String>) -> Self {
        self.parameters.push(param.into());
        self
    }

    /// Adds history to the context.
    pub fn with_history(mut self, history: Vec<String>) -> Self {
        self.history = history;
        self
    }
}

/// Trait for ethical evaluators.
///
/// Evaluators analyze proposed actions and vote on their safety
/// based on a specific ethical framework.
///
/// # Implementors
///
/// - [`triad::Deontologist`]: Rule-based evaluation
/// - [`triad::Consequentialist`]: Outcome-based evaluation
/// - [`triad::Logicist`]: Logical validity evaluation
pub trait Evaluator: Send + Sync {
    /// Returns the name of this evaluator.
    fn name(&self) -> &str;

    /// Returns a description of this evaluator's ethical framework.
    fn framework(&self) -> &str;

    /// Evaluates a proposed action and returns a vote.
    ///
    /// # Arguments
    /// * `context` - The evaluation context containing action details
    ///
    /// # Returns
    /// An [`EvaluatorVote`] with the decision, confidence, and reasoning.
    fn evaluate(&self, context: &EvaluationContext) -> EvaluatorVote;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_new_valid() {
        let c = Confidence::new(0.5);
        assert!((c.value() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    #[should_panic(expected = "Confidence must be between 0.0 and 1.0")]
    fn test_confidence_new_invalid_high() {
        Confidence::new(1.5);
    }

    #[test]
    #[should_panic(expected = "Confidence must be between 0.0 and 1.0")]
    fn test_confidence_new_invalid_low() {
        Confidence::new(-0.1);
    }

    #[test]
    fn test_confidence_presets() {
        assert!((Confidence::high().value() - 0.9).abs() < f64::EPSILON);
        assert!((Confidence::medium().value() - 0.6).abs() < f64::EPSILON);
        assert!((Confidence::low().value() - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_confidence_display() {
        let c = Confidence::new(0.75);
        assert_eq!(c.to_string(), "75.0%");
    }

    #[test]
    fn test_decision_display() {
        assert_eq!(Decision::Approve.to_string(), "APPROVE");
        assert_eq!(Decision::Reject.to_string(), "REJECT");
        assert_eq!(Decision::Abstain.to_string(), "ABSTAIN");
    }

    #[test]
    fn test_evaluator_vote_new() {
        let vote = EvaluatorVote::new(
            "TestEvaluator",
            Decision::Approve,
            Confidence::high(),
            "All good",
        );
        assert_eq!(vote.evaluator, "TestEvaluator");
        assert_eq!(vote.decision, Decision::Approve);
        assert_eq!(vote.reasoning, "All good");
    }

    #[test]
    fn test_evaluator_vote_approve() {
        let vote = EvaluatorVote::approve("Test", Confidence::high(), "Safe");
        assert_eq!(vote.decision, Decision::Approve);
    }

    #[test]
    fn test_evaluator_vote_reject() {
        let vote = EvaluatorVote::reject("Test", Confidence::high(), "Unsafe");
        assert_eq!(vote.decision, Decision::Reject);
    }

    #[test]
    fn test_evaluator_vote_abstain() {
        let vote = EvaluatorVote::abstain("Test", "Cannot determine");
        assert_eq!(vote.decision, Decision::Abstain);
    }

    #[test]
    fn test_evaluation_context_new() {
        let ctx = EvaluationContext::new("read", "/tmp/file.txt");
        assert_eq!(ctx.action, "read");
        assert_eq!(ctx.target, "/tmp/file.txt");
        assert!(ctx.parameters.is_empty());
    }

    #[test]
    fn test_evaluation_context_with_parameter() {
        let ctx = EvaluationContext::new("write", "/tmp/file.txt")
            .with_parameter("--force")
            .with_parameter("--recursive");
        assert_eq!(ctx.parameters.len(), 2);
        assert_eq!(ctx.parameters[0], "--force");
    }

    #[test]
    fn test_evaluation_context_with_history() {
        let history = vec!["read /etc/passwd".to_string()];
        let ctx = EvaluationContext::new("write", "/etc/passwd").with_history(history);
        assert_eq!(ctx.history.len(), 1);
    }
}
