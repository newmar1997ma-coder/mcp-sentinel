//! # Cognitive Council
//!
//! Multi-model consensus voting with ethical triad evaluation.
//! Defends against single-model compromise and Waluigi Effect.
//!
//! ## Overview
//!
//! The Cognitive Council provides a Byzantine fault-tolerant voting system
//! for evaluating AI action safety. Three independent evaluators with
//! different ethical frameworks vote on proposed actions, requiring 2/3
//! majority for approval.
//!
//! ## Threat Model
//!
//! ### Single Model Compromise
//! If one model is jailbroken or manipulated, the consensus mechanism
//! ensures the compromised vote is outvoted by the remaining honest
//! evaluators. This follows Byzantine fault tolerance principles where
//! the system tolerates f < n/3 faulty nodes.
//!
//! ### Waluigi Effect
//! The Waluigi Effect describes how language models can exhibit inverted
//! alignment after exposure to jailbreak prompts. Named after the Mario
//! character who is Luigi's evil opposite, a "Waluigi'd" model produces
//! outputs that systematically oppose its intended behavior.
//!
//! The Waluigi detector analyzes response patterns for signs of alignment
//! inversion and can veto actions regardless of consensus vote.
//!
//! ### Ethical Blind Spots
//! A single ethical framework may have blind spots. The triad approach
//! covers three complementary perspectives:
//! - **Deontologist**: Rule-based evaluation (duty and obligation)
//! - **Consequentialist**: Outcome-based evaluation (results and effects)
//! - **Logicist**: Logical validity (consistency and soundness)
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
//! │ Deontologist│  │Consequentialist│ │  Logicist  │
//! │  (Rules)    │  │  (Outcomes)  │  │ (Validity) │
//! └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
//!        │                │                │
//!        └────────────────┼────────────────┘
//!                         ▼
//!                  ┌─────────────┐
//!                  │  CONSENSUS  │
//!                  │   VOTING    │
//!                  └──────┬──────┘
//!                         ▼
//!                  ┌─────────────┐
//!                  │  WALUIGI    │
//!                  │  DETECTOR   │
//!                  └─────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use sentinel_council::{CognitiveCouncil, ActionProposal};
//!
//! let council = CognitiveCouncil::new();
//! let proposal = ActionProposal::new("file_write", "/etc/passwd");
//!
//! match council.evaluate(&proposal).await {
//!     CouncilVerdict::Approved { votes } => {
//!         // Action is safe to execute
//!     }
//!     CouncilVerdict::Rejected { reason, votes } => {
//!         // Action blocked with explanation
//!     }
//!     CouncilVerdict::WaluigiVeto { score } => {
//!         // Alignment inversion detected
//!     }
//! }
//! ```
//!
//! ## References
//!
//! - [The Waluigi Effect](https://www.lesswrong.com/posts/D7PuSMfLJhd8sSxKR/the-waluigi-effect-mega-post) - LessWrong, 2023
//! - [Byzantine Fault Tolerance](https://en.wikipedia.org/wiki/Byzantine_fault) - Consensus under adversarial conditions
//! - [Moral Philosophy Frameworks](https://plato.stanford.edu/entries/ethics-virtue/) - Stanford Encyclopedia of Philosophy

pub mod evaluator;
pub mod consensus;
pub mod waluigi;
pub mod council;
pub mod error;

pub use evaluator::{Evaluator, EvaluatorVote, Confidence};
pub use evaluator::triad::{Deontologist, Consequentialist, Logicist};
pub use consensus::{ConsensusEngine, ConsensusResult, VoteTally};
pub use waluigi::{WaluigiDetector, WaluigiScore, InversionPattern};
pub use council::{CognitiveCouncil, CouncilVerdict, ActionProposal};
pub use error::CouncilError;

/// Result type for council operations.
pub type Result<T> = std::result::Result<T, CouncilError>;

#[cfg(test)]
mod tests {
    #[test]
    fn test_crate_compiles() {
        // Smoke test - if this compiles, the crate structure is valid
        let _ = std::hint::black_box(1);
    }
}
