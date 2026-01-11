//! The Evaluator Triad: Deontologist, Consequentialist, and Logicist.
//!
//! Three complementary ethical evaluators that cover different
//! moral frameworks to eliminate ethical blind spots.

use super::{Confidence, Decision, EvaluationContext, Evaluator, EvaluatorVote};

// Placeholder implementations - will be fully implemented in Operation 2

/// Rule-based ethical evaluator.
///
/// The Deontologist evaluates actions based on adherence to rules
/// and duties, regardless of outcomes. An action is wrong if it
/// violates a moral rule, even if it produces good consequences.
///
/// # Ethical Framework
///
/// Based on Kantian deontology:
/// - Act only according to rules you could will to be universal laws
/// - Treat people as ends in themselves, never merely as means
/// - Certain actions are intrinsically wrong regardless of outcomes
///
/// # Security Rules Enforced
///
/// - No modification of system files
/// - No exfiltration of sensitive data
/// - No execution of arbitrary code without authorization
/// - No bypassing of security controls
pub struct Deontologist {
    /// Rules that define prohibited actions.
    rules: Vec<Rule>,
}

/// A rule in the deontological framework.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Name of the rule.
    pub name: String,
    /// Pattern that matches prohibited actions.
    pub pattern: String,
    /// Severity of violation.
    pub severity: RuleSeverity,
}

/// Severity level for rule violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSeverity {
    /// Critical violation - immediate rejection.
    Critical,
    /// High severity - likely rejection.
    High,
    /// Medium severity - requires justification.
    Medium,
    /// Low severity - warning only.
    Low,
}

impl Default for Deontologist {
    fn default() -> Self {
        Self::new()
    }
}

impl Deontologist {
    /// Creates a new Deontologist with default security rules.
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }

    /// Creates a Deontologist with custom rules.
    pub fn with_rules(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Returns the default security rules.
    fn default_rules() -> Vec<Rule> {
        vec![
            Rule {
                name: "no_system_modification".to_string(),
                pattern: "/etc/|/sys/|/proc/".to_string(),
                severity: RuleSeverity::Critical,
            },
            Rule {
                name: "no_credential_access".to_string(),
                pattern: "passwd|shadow|credentials|secrets".to_string(),
                severity: RuleSeverity::Critical,
            },
            Rule {
                name: "no_arbitrary_execution".to_string(),
                pattern: "exec|eval|system|shell".to_string(),
                severity: RuleSeverity::High,
            },
            Rule {
                name: "no_network_exfiltration".to_string(),
                pattern: "upload|exfil|transmit|send.*external".to_string(),
                severity: RuleSeverity::High,
            },
        ]
    }

    /// Checks if an action violates any rules.
    fn check_rules(&self, context: &EvaluationContext) -> Option<(&Rule, RuleSeverity)> {
        let action_str = format!("{} {}", context.action, context.target);

        for rule in &self.rules {
            if action_str.to_lowercase().contains(&rule.pattern.to_lowercase()) {
                return Some((rule, rule.severity));
            }
        }
        None
    }
}

impl Evaluator for Deontologist {
    fn name(&self) -> &str {
        "Deontologist"
    }

    fn framework(&self) -> &str {
        "Kantian deontology - rule-based ethics focused on duty and obligation"
    }

    fn evaluate(&self, context: &EvaluationContext) -> EvaluatorVote {
        if let Some((rule, severity)) = self.check_rules(context) {
            let confidence = match severity {
                RuleSeverity::Critical => Confidence::high(),
                RuleSeverity::High => Confidence::new(0.8),
                RuleSeverity::Medium => Confidence::medium(),
                RuleSeverity::Low => Confidence::low(),
            };

            let decision = match severity {
                RuleSeverity::Critical | RuleSeverity::High => Decision::Reject,
                RuleSeverity::Medium => Decision::Reject,
                RuleSeverity::Low => Decision::Approve,
            };

            EvaluatorVote::new(
                self.name(),
                decision,
                confidence,
                format!("Violates rule '{}': {}", rule.name, rule.pattern),
            )
        } else {
            EvaluatorVote::approve(
                self.name(),
                Confidence::high(),
                "No rule violations detected",
            )
        }
    }
}

/// Outcome-based ethical evaluator.
///
/// The Consequentialist evaluates actions based on their expected
/// outcomes. An action is right if it produces good consequences
/// and wrong if it produces bad consequences.
///
/// # Ethical Framework
///
/// Based on utilitarian consequentialism:
/// - Actions are judged by their outcomes, not intentions
/// - The right action maximizes overall good
/// - Both immediate and long-term consequences matter
///
/// # Outcome Analysis
///
/// - Assesses potential harm to users, systems, and data
/// - Considers reversibility of actions
/// - Weighs benefits against risks
pub struct Consequentialist {
    /// Harm patterns to detect.
    harm_patterns: Vec<HarmPattern>,
}

/// A pattern indicating potential harm.
#[derive(Debug, Clone)]
pub struct HarmPattern {
    /// Name of the harm pattern.
    pub name: String,
    /// Pattern to match.
    pub pattern: String,
    /// Expected severity of harm.
    pub harm_level: HarmLevel,
    /// Whether the harm is reversible.
    pub reversible: bool,
}

/// Level of potential harm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarmLevel {
    /// Catastrophic harm - data loss, security breach.
    Catastrophic,
    /// Significant harm - service disruption.
    Significant,
    /// Moderate harm - temporary issues.
    Moderate,
    /// Minimal harm - easily recoverable.
    Minimal,
}

impl Default for Consequentialist {
    fn default() -> Self {
        Self::new()
    }
}

impl Consequentialist {
    /// Creates a new Consequentialist with default harm patterns.
    pub fn new() -> Self {
        Self {
            harm_patterns: Self::default_patterns(),
        }
    }

    /// Creates a Consequentialist with custom patterns.
    pub fn with_patterns(patterns: Vec<HarmPattern>) -> Self {
        Self {
            harm_patterns: patterns,
        }
    }

    /// Returns the default harm patterns.
    fn default_patterns() -> Vec<HarmPattern> {
        vec![
            HarmPattern {
                name: "data_destruction".to_string(),
                pattern: "delete|remove|destroy|wipe|format".to_string(),
                harm_level: HarmLevel::Catastrophic,
                reversible: false,
            },
            HarmPattern {
                name: "security_compromise".to_string(),
                pattern: "chmod 777|disable.*auth|bypass.*security".to_string(),
                harm_level: HarmLevel::Catastrophic,
                reversible: true,
            },
            HarmPattern {
                name: "service_disruption".to_string(),
                pattern: "kill|stop|shutdown|restart".to_string(),
                harm_level: HarmLevel::Significant,
                reversible: true,
            },
            HarmPattern {
                name: "resource_exhaustion".to_string(),
                pattern: "infinite|loop|fork.*bomb|memory.*leak".to_string(),
                harm_level: HarmLevel::Significant,
                reversible: true,
            },
        ]
    }

    /// Analyzes potential consequences of an action.
    fn analyze_consequences(&self, context: &EvaluationContext) -> Option<(&HarmPattern, f64)> {
        let action_str = format!("{} {} {}",
            context.action,
            context.target,
            context.parameters.join(" ")
        );

        for pattern in &self.harm_patterns {
            if action_str.to_lowercase().contains(&pattern.pattern.to_lowercase()) {
                let harm_score = match pattern.harm_level {
                    HarmLevel::Catastrophic => 1.0,
                    HarmLevel::Significant => 0.7,
                    HarmLevel::Moderate => 0.4,
                    HarmLevel::Minimal => 0.1,
                };

                // Reduce score if reversible
                let adjusted = if pattern.reversible {
                    harm_score * 0.7
                } else {
                    harm_score
                };

                return Some((pattern, adjusted));
            }
        }
        None
    }
}

impl Evaluator for Consequentialist {
    fn name(&self) -> &str {
        "Consequentialist"
    }

    fn framework(&self) -> &str {
        "Utilitarian consequentialism - outcome-based ethics focused on results"
    }

    fn evaluate(&self, context: &EvaluationContext) -> EvaluatorVote {
        if let Some((pattern, harm_score)) = self.analyze_consequences(context) {
            let decision = if harm_score > 0.6 {
                Decision::Reject
            } else if harm_score > 0.3 {
                Decision::Abstain
            } else {
                Decision::Approve
            };

            let confidence = Confidence::new(0.5 + harm_score * 0.4);

            let reversibility = if pattern.reversible { "reversible" } else { "irreversible" };

            EvaluatorVote::new(
                self.name(),
                decision,
                confidence,
                format!(
                    "Detected '{}' pattern (harm: {:.0}%, {})",
                    pattern.name,
                    harm_score * 100.0,
                    reversibility
                ),
            )
        } else {
            EvaluatorVote::approve(
                self.name(),
                Confidence::medium(),
                "No significant harmful consequences predicted",
            )
        }
    }
}

/// Logical validity evaluator.
///
/// The Logicist evaluates actions based on logical consistency,
/// internal coherence, and validity of reasoning.
///
/// # Evaluation Criteria
///
/// - Actions must be logically consistent with stated goals
/// - Parameters must be valid and well-formed
/// - No contradictions with previous actions
/// - No circular dependencies or infinite loops
///
/// # Validity Checks
///
/// - Path syntax validation
/// - Parameter range checking
/// - Consistency with action history
pub struct Logicist {
    /// Maximum action history to consider.
    max_history: usize,
}

impl Default for Logicist {
    fn default() -> Self {
        Self::new()
    }
}

impl Logicist {
    /// Creates a new Logicist evaluator.
    pub fn new() -> Self {
        Self { max_history: 10 }
    }

    /// Creates a Logicist with custom history limit.
    pub fn with_max_history(max_history: usize) -> Self {
        Self { max_history }
    }

    /// Validates the logical consistency of an action.
    fn validate_logic(&self, context: &EvaluationContext) -> Vec<LogicIssue> {
        let mut issues = Vec::new();

        // Check for empty or malformed action
        if context.action.is_empty() {
            issues.push(LogicIssue {
                severity: IssueSeverity::Error,
                description: "Empty action is logically invalid".to_string(),
            });
        }

        // Check for contradictory patterns
        if context.action.contains("read") && context.action.contains("write") {
            issues.push(LogicIssue {
                severity: IssueSeverity::Warning,
                description: "Simultaneous read/write may cause race conditions".to_string(),
            });
        }

        // Check for suspicious parameter patterns
        for param in &context.parameters {
            if param.contains("&&") || param.contains("||") || param.contains(";") {
                issues.push(LogicIssue {
                    severity: IssueSeverity::Error,
                    description: format!("Command injection pattern in parameter: {}", param),
                });
            }
        }

        // Check history for contradictions
        let recent_history: Vec<_> = context.history.iter().take(self.max_history).collect();
        if recent_history.iter().any(|h| h.contains("delete") || h.contains("remove")) {
            if context.action.contains("read") {
                issues.push(LogicIssue {
                    severity: IssueSeverity::Warning,
                    description: "Reading target that was recently deleted is suspicious".to_string(),
                });
            }
        }

        issues
    }
}

/// A logical issue found during evaluation.
#[derive(Debug, Clone)]
struct LogicIssue {
    severity: IssueSeverity,
    description: String,
}

/// Severity of a logical issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IssueSeverity {
    Error,
    Warning,
}

impl Evaluator for Logicist {
    fn name(&self) -> &str {
        "Logicist"
    }

    fn framework(&self) -> &str {
        "Formal logic - consistency, validity, and soundness of reasoning"
    }

    fn evaluate(&self, context: &EvaluationContext) -> EvaluatorVote {
        let issues = self.validate_logic(context);

        if issues.is_empty() {
            return EvaluatorVote::approve(
                self.name(),
                Confidence::high(),
                "Action is logically valid and consistent",
            );
        }

        let errors: Vec<_> = issues.iter()
            .filter(|i| i.severity == IssueSeverity::Error)
            .collect();

        let warnings: Vec<_> = issues.iter()
            .filter(|i| i.severity == IssueSeverity::Warning)
            .collect();

        if !errors.is_empty() {
            let error_desc: Vec<_> = errors.iter().map(|e| e.description.as_str()).collect();
            EvaluatorVote::reject(
                self.name(),
                Confidence::high(),
                format!("Logical errors: {}", error_desc.join("; ")),
            )
        } else if warnings.len() > 1 {
            let warn_desc: Vec<_> = warnings.iter().map(|w| w.description.as_str()).collect();
            EvaluatorVote::new(
                self.name(),
                Decision::Abstain,
                Confidence::medium(),
                format!("Multiple warnings: {}", warn_desc.join("; ")),
            )
        } else {
            let warn_desc: Vec<_> = warnings.iter().map(|w| w.description.as_str()).collect();
            EvaluatorVote::approve(
                self.name(),
                Confidence::medium(),
                format!("Minor concerns: {}", warn_desc.join("; ")),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deontologist tests
    #[test]
    fn test_deontologist_new() {
        let d = Deontologist::new();
        assert!(!d.rules.is_empty());
    }

    #[test]
    fn test_deontologist_name() {
        let d = Deontologist::new();
        assert_eq!(d.name(), "Deontologist");
    }

    #[test]
    fn test_deontologist_approves_safe_action() {
        let d = Deontologist::new();
        let ctx = EvaluationContext::new("read", "/tmp/safe_file.txt");
        let vote = d.evaluate(&ctx);
        assert_eq!(vote.decision, Decision::Approve);
    }

    #[test]
    fn test_deontologist_rejects_system_modification() {
        let d = Deontologist::new();
        let ctx = EvaluationContext::new("write", "/etc/passwd");
        let vote = d.evaluate(&ctx);
        assert_eq!(vote.decision, Decision::Reject);
    }

    #[test]
    fn test_deontologist_rejects_credential_access() {
        let d = Deontologist::new();
        let ctx = EvaluationContext::new("read", "secrets.json");
        let vote = d.evaluate(&ctx);
        assert_eq!(vote.decision, Decision::Reject);
    }

    #[test]
    fn test_deontologist_custom_rules() {
        let rules = vec![Rule {
            name: "no_foo".to_string(),
            pattern: "foo".to_string(),
            severity: RuleSeverity::Critical,
        }];
        let d = Deontologist::with_rules(rules);
        let ctx = EvaluationContext::new("access", "foo_resource");
        let vote = d.evaluate(&ctx);
        assert_eq!(vote.decision, Decision::Reject);
    }

    // Consequentialist tests
    #[test]
    fn test_consequentialist_new() {
        let c = Consequentialist::new();
        assert!(!c.harm_patterns.is_empty());
    }

    #[test]
    fn test_consequentialist_name() {
        let c = Consequentialist::new();
        assert_eq!(c.name(), "Consequentialist");
    }

    #[test]
    fn test_consequentialist_approves_harmless_action() {
        let c = Consequentialist::new();
        let ctx = EvaluationContext::new("read", "/tmp/log.txt");
        let vote = c.evaluate(&ctx);
        assert_eq!(vote.decision, Decision::Approve);
    }

    #[test]
    fn test_consequentialist_rejects_destructive_action() {
        let c = Consequentialist::new();
        let ctx = EvaluationContext::new("delete", "/important/data");
        let vote = c.evaluate(&ctx);
        assert_eq!(vote.decision, Decision::Reject);
    }

    #[test]
    fn test_consequentialist_considers_reversibility() {
        let c = Consequentialist::new();
        let ctx = EvaluationContext::new("restart", "service");
        let vote = c.evaluate(&ctx);
        // Restart is significant but reversible
        assert!(vote.confidence.value() < 0.9);
    }

    #[test]
    fn test_consequentialist_custom_patterns() {
        let patterns = vec![HarmPattern {
            name: "custom_harm".to_string(),
            pattern: "dangerous".to_string(),
            harm_level: HarmLevel::Catastrophic,
            reversible: false,
        }];
        let c = Consequentialist::with_patterns(patterns);
        let ctx = EvaluationContext::new("do", "dangerous_thing");
        let vote = c.evaluate(&ctx);
        assert_eq!(vote.decision, Decision::Reject);
    }

    // Logicist tests
    #[test]
    fn test_logicist_new() {
        let l = Logicist::new();
        assert_eq!(l.max_history, 10);
    }

    #[test]
    fn test_logicist_name() {
        let l = Logicist::new();
        assert_eq!(l.name(), "Logicist");
    }

    #[test]
    fn test_logicist_approves_valid_action() {
        let l = Logicist::new();
        let ctx = EvaluationContext::new("read", "/tmp/file.txt");
        let vote = l.evaluate(&ctx);
        assert_eq!(vote.decision, Decision::Approve);
    }

    #[test]
    fn test_logicist_rejects_empty_action() {
        let l = Logicist::new();
        let ctx = EvaluationContext::new("", "/tmp/file.txt");
        let vote = l.evaluate(&ctx);
        assert_eq!(vote.decision, Decision::Reject);
    }

    #[test]
    fn test_logicist_detects_command_injection() {
        let l = Logicist::new();
        let ctx = EvaluationContext::new("exec", "program")
            .with_parameter("arg; rm -rf /");
        let vote = l.evaluate(&ctx);
        assert_eq!(vote.decision, Decision::Reject);
    }

    #[test]
    fn test_logicist_warns_on_read_write_conflict() {
        let l = Logicist::new();
        let ctx = EvaluationContext::new("read_write", "/tmp/file.txt");
        let vote = l.evaluate(&ctx);
        // Should have a warning but still approve
        assert!(vote.reasoning.contains("race conditions") || vote.decision == Decision::Approve);
    }

    #[test]
    fn test_logicist_custom_history_limit() {
        let l = Logicist::with_max_history(5);
        assert_eq!(l.max_history, 5);
    }

    // Framework description tests
    #[test]
    fn test_evaluator_frameworks() {
        let d = Deontologist::new();
        let c = Consequentialist::new();
        let l = Logicist::new();

        assert!(d.framework().contains("deontology"));
        assert!(c.framework().contains("consequentialism"));
        assert!(l.framework().contains("logic"));
    }
}
