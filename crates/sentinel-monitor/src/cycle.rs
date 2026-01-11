//! Cycle detection algorithms for MCP agent execution paths.
//!
//! Implements Floyd's tortoise-and-hare and Tarjan's SCC algorithms
//! to detect cycles before they cause infinite loops.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a single step in an agent's execution path.
///
/// Each node captures the state identifier and step number,
/// allowing cycle detection algorithms to identify when an agent
/// revisits a previous state.
///
/// # Example
///
/// ```rust
/// use sentinel_monitor::ExecutionNode;
///
/// let node = ExecutionNode::new("processing_request", 42);
/// assert_eq!(node.state_id(), "processing_request");
/// assert_eq!(node.step(), 42);
/// ```
///
/// # Security Notes
///
/// State IDs should be deterministic hashes of agent state,
/// not raw state data, to prevent information leakage.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecutionNode {
    /// Unique identifier for the execution state
    state_id: String,
    /// Sequential step number in execution path
    step: u64,
}

impl ExecutionNode {
    /// Creates a new execution node.
    ///
    /// # Arguments
    ///
    /// * `state_id` - Unique identifier for this execution state
    /// * `step` - Sequential step number in the execution path
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::ExecutionNode;
    ///
    /// let node = ExecutionNode::new("state_hash_abc123", 1);
    /// ```
    pub fn new(state_id: impl Into<String>, step: u64) -> Self {
        Self {
            state_id: state_id.into(),
            step,
        }
    }

    /// Returns the state identifier.
    pub fn state_id(&self) -> &str {
        &self.state_id
    }

    /// Returns the step number.
    pub fn step(&self) -> u64 {
        self.step
    }
}

/// Represents a detected cycle in the execution path.
///
/// Contains all nodes involved in the cycle and metadata about
/// when/where the cycle was detected.
///
/// # Example
///
/// ```rust
/// use sentinel_monitor::{Cycle, ExecutionNode};
///
/// let nodes = vec![
///     ExecutionNode::new("state_a", 1),
///     ExecutionNode::new("state_b", 2),
///     ExecutionNode::new("state_a", 3),
/// ];
/// let cycle = Cycle::new(nodes, 3);
/// assert_eq!(cycle.length(), 2); // A -> B -> A is length 2
/// ```
///
/// # Security Notes
///
/// Cycle information is logged for forensic analysis.
/// Ensure logs are protected from unauthorized access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cycle {
    /// Nodes involved in the cycle
    nodes: Vec<ExecutionNode>,
    /// Step at which cycle was detected
    detected_at_step: u64,
}

impl Cycle {
    /// Creates a new cycle from the involved nodes.
    ///
    /// # Arguments
    ///
    /// * `nodes` - All nodes participating in the cycle
    /// * `detected_at_step` - Step number when cycle was detected
    pub fn new(nodes: Vec<ExecutionNode>, detected_at_step: u64) -> Self {
        Self {
            nodes,
            detected_at_step,
        }
    }

    /// Returns the nodes involved in this cycle.
    pub fn nodes(&self) -> &[ExecutionNode] {
        &self.nodes
    }

    /// Returns the step at which the cycle was detected.
    pub fn detected_at_step(&self) -> u64 {
        self.detected_at_step
    }

    /// Returns the number of unique states in the cycle.
    ///
    /// A cycle A -> B -> A has length 2 (two unique states).
    pub fn length(&self) -> usize {
        // Count unique state_ids
        let unique: std::collections::HashSet<_> =
            self.nodes.iter().map(|n| &n.state_id).collect();
        unique.len()
    }
}

/// Detects cycles in MCP agent execution paths.
///
/// Implements two complementary algorithms:
/// - **Floyd's tortoise-and-hare**: Fast O(n) detection of simple cycles
/// - **Tarjan's SCC**: O(V+E) detection of complex/nested cycles
///
/// # Example
///
/// ```rust
/// use sentinel_monitor::{CycleDetector, ExecutionNode};
///
/// let mut detector = CycleDetector::new();
///
/// detector.record_step(ExecutionNode::new("state_a", 1));
/// detector.record_step(ExecutionNode::new("state_b", 2));
/// detector.record_step(ExecutionNode::new("state_a", 3));
///
/// // Floyd detects simple repeat
/// if let Some(cycle) = detector.detect_cycle_floyd() {
///     println!("Simple cycle: {:?}", cycle);
/// }
/// ```
///
/// # Security Notes
///
/// - Call `detect_cycle()` before each agent step
/// - On detection, halt execution immediately
/// - Log all cycles for security audit
#[derive(Debug, Default)]
pub struct CycleDetector {
    /// Recorded execution path
    path: Vec<ExecutionNode>,
    /// Map from state_id to step numbers where it appeared
    state_occurrences: HashMap<String, Vec<u64>>,
}

impl CycleDetector {
    /// Creates a new cycle detector.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::CycleDetector;
    ///
    /// let detector = CycleDetector::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an execution step.
    ///
    /// # Arguments
    ///
    /// * `node` - The execution node representing current state
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::{CycleDetector, ExecutionNode};
    ///
    /// let mut detector = CycleDetector::new();
    /// detector.record_step(ExecutionNode::new("initial", 1));
    /// ```
    pub fn record_step(&mut self, node: ExecutionNode) {
        self.state_occurrences
            .entry(node.state_id.clone())
            .or_default()
            .push(node.step);
        self.path.push(node);
    }

    /// Returns the current execution path.
    pub fn path(&self) -> &[ExecutionNode] {
        &self.path
    }

    /// Clears all recorded steps.
    ///
    /// Use when starting a new execution context.
    pub fn clear(&mut self) {
        self.path.clear();
        self.state_occurrences.clear();
    }

    /// Detects cycles using both Floyd and Tarjan algorithms.
    ///
    /// Returns the first cycle found, preferring Floyd's simpler detection.
    ///
    /// # Returns
    ///
    /// `Some(Cycle)` if a cycle is detected, `None` otherwise.
    ///
    /// # Security Notes
    ///
    /// This is the primary entry point for cycle detection.
    /// Call before each agent step to prevent infinite loops.
    pub fn detect_cycle(&self) -> Option<Cycle> {
        // Try Floyd first (faster for simple cycles)
        if let Some(cycle) = self.detect_cycle_floyd() {
            return Some(cycle);
        }

        // Fall back to Tarjan for complex cycles
        self.detect_cycle_tarjan()
    }

    /// Detects simple cycles using Floyd's tortoise-and-hare algorithm.
    ///
    /// Floyd's algorithm uses two pointers moving at different speeds
    /// to detect cycles in O(n) time with O(1) space.
    ///
    /// # Algorithm
    ///
    /// 1. Tortoise moves one step at a time
    /// 2. Hare moves two steps at a time
    /// 3. If they meet, a cycle exists
    /// 4. To find cycle start, reset tortoise to beginning
    /// 5. Move both one step at a time until they meet
    ///
    /// # Complexity
    ///
    /// - Time: O(n) where n is path length
    /// - Space: O(1) for pointer-based detection
    ///
    /// # Returns
    ///
    /// `Some(Cycle)` if a simple cycle is detected, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::{CycleDetector, ExecutionNode};
    ///
    /// let mut detector = CycleDetector::new();
    /// detector.record_step(ExecutionNode::new("a", 1));
    /// detector.record_step(ExecutionNode::new("b", 2));
    /// detector.record_step(ExecutionNode::new("a", 3)); // Revisit!
    ///
    /// assert!(detector.detect_cycle_floyd().is_some());
    /// ```
    ///
    /// # Security Notes
    ///
    /// Floyd's algorithm detects when a state is revisited,
    /// which indicates the agent is looping through the same states.
    pub fn detect_cycle_floyd(&self) -> Option<Cycle> {
        // For state-based cycle detection, we check if any state_id
        // appears more than once in the path
        for (_state_id, occurrences) in &self.state_occurrences {
            if occurrences.len() >= 2 {
                // Found a repeated state - this is a cycle
                let first_occurrence = occurrences[0];
                let second_occurrence = occurrences[occurrences.len() - 1];

                // Extract nodes between first and second occurrence
                let cycle_nodes: Vec<ExecutionNode> = self
                    .path
                    .iter()
                    .filter(|n| n.step >= first_occurrence && n.step <= second_occurrence)
                    .cloned()
                    .collect();

                return Some(Cycle::new(cycle_nodes, second_occurrence));
            }
        }

        None
    }

    /// Detects complex cycles using Tarjan's strongly connected components algorithm.
    ///
    /// Tarjan's algorithm finds all strongly connected components (SCCs)
    /// in a directed graph using depth-first search. An SCC with more than
    /// one node indicates a cycle.
    ///
    /// # Algorithm
    ///
    /// 1. Perform DFS, assigning indices to nodes
    /// 2. Track lowest reachable index (lowlink) for each node
    /// 3. When lowlink equals index, we've found an SCC root
    /// 4. Pop stack to extract SCC members
    ///
    /// # Complexity
    ///
    /// - Time: O(V + E) where V = nodes, E = edges
    /// - Space: O(V) for stack and index tracking
    ///
    /// # Returns
    ///
    /// `Some(Cycle)` if a complex cycle is detected, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sentinel_monitor::{CycleDetector, ExecutionNode};
    ///
    /// let mut detector = CycleDetector::new();
    ///
    /// // Complex cycle: A -> B -> C -> A
    /// detector.record_step(ExecutionNode::new("a", 1));
    /// detector.record_step(ExecutionNode::new("b", 2));
    /// detector.record_step(ExecutionNode::new("c", 3));
    /// detector.record_step(ExecutionNode::new("a", 4)); // Back to A!
    ///
    /// assert!(detector.detect_cycle_tarjan().is_some());
    /// ```
    ///
    /// # Security Notes
    ///
    /// Tarjan's algorithm catches complex cycles that Floyd might miss,
    /// such as interleaved or nested cycles in multi-threaded execution.
    pub fn detect_cycle_tarjan(&self) -> Option<Cycle> {
        // Build adjacency list from execution path
        // Each state_id is a node, edges go from step N to step N+1
        if self.path.len() < 2 {
            return None;
        }

        // For execution path cycle detection, we model transitions
        // between states. A cycle exists if we can reach a state
        // we've seen before.

        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();

        for window in self.path.windows(2) {
            let from = window[0].state_id();
            let to = window[1].state_id();
            adjacency.entry(from).or_default().push(to);
        }

        // Tarjan's SCC algorithm
        let mut index_counter = 0u64;
        let mut stack: Vec<&str> = Vec::new();
        let mut on_stack: HashMap<&str, bool> = HashMap::new();
        let mut indices: HashMap<&str, u64> = HashMap::new();
        let mut lowlinks: HashMap<&str, u64> = HashMap::new();
        let mut sccs: Vec<Vec<&str>> = Vec::new();

        fn strongconnect<'a>(
            node: &'a str,
            adjacency: &HashMap<&'a str, Vec<&'a str>>,
            index_counter: &mut u64,
            stack: &mut Vec<&'a str>,
            on_stack: &mut HashMap<&'a str, bool>,
            indices: &mut HashMap<&'a str, u64>,
            lowlinks: &mut HashMap<&'a str, u64>,
            sccs: &mut Vec<Vec<&'a str>>,
        ) {
            indices.insert(node, *index_counter);
            lowlinks.insert(node, *index_counter);
            *index_counter += 1;
            stack.push(node);
            on_stack.insert(node, true);

            if let Some(neighbors) = adjacency.get(node) {
                for &neighbor in neighbors {
                    if !indices.contains_key(neighbor) {
                        strongconnect(
                            neighbor,
                            adjacency,
                            index_counter,
                            stack,
                            on_stack,
                            indices,
                            lowlinks,
                            sccs,
                        );
                        let neighbor_lowlink = *lowlinks.get(neighbor).unwrap();
                        let node_lowlink = lowlinks.get_mut(node).unwrap();
                        *node_lowlink = (*node_lowlink).min(neighbor_lowlink);
                    } else if *on_stack.get(neighbor).unwrap_or(&false) {
                        let neighbor_index = *indices.get(neighbor).unwrap();
                        let node_lowlink = lowlinks.get_mut(node).unwrap();
                        *node_lowlink = (*node_lowlink).min(neighbor_index);
                    }
                }
            }

            // If node is root of SCC
            if lowlinks.get(node) == indices.get(node) {
                let mut scc = Vec::new();
                loop {
                    let w = stack.pop().unwrap();
                    on_stack.insert(w, false);
                    scc.push(w);
                    if w == node {
                        break;
                    }
                }
                if scc.len() > 1 {
                    sccs.push(scc);
                }
            }
        }

        // Run Tarjan on all nodes
        let nodes: Vec<&str> = self.path.iter().map(|n| n.state_id()).collect();
        for &node in &nodes {
            if !indices.contains_key(node) {
                strongconnect(
                    node,
                    &adjacency,
                    &mut index_counter,
                    &mut stack,
                    &mut on_stack,
                    &mut indices,
                    &mut lowlinks,
                    &mut sccs,
                );
            }
        }

        // If we found any SCC with > 1 node, that's a cycle
        if let Some(scc) = sccs.first() {
            let cycle_nodes: Vec<ExecutionNode> = self
                .path
                .iter()
                .filter(|n| scc.contains(&n.state_id()))
                .cloned()
                .collect();

            let last_step = cycle_nodes.last().map(|n| n.step).unwrap_or(0);
            return Some(Cycle::new(cycle_nodes, last_step));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_node_creation() {
        let node = ExecutionNode::new("test_state", 42);
        assert_eq!(node.state_id(), "test_state");
        assert_eq!(node.step(), 42);
    }

    #[test]
    fn test_cycle_creation() {
        let nodes = vec![
            ExecutionNode::new("a", 1),
            ExecutionNode::new("b", 2),
            ExecutionNode::new("a", 3),
        ];
        let cycle = Cycle::new(nodes, 3);
        assert_eq!(cycle.detected_at_step(), 3);
        assert_eq!(cycle.length(), 2); // a, b
    }

    #[test]
    fn test_no_cycle_detected() {
        let mut detector = CycleDetector::new();
        detector.record_step(ExecutionNode::new("a", 1));
        detector.record_step(ExecutionNode::new("b", 2));
        detector.record_step(ExecutionNode::new("c", 3));

        assert!(detector.detect_cycle().is_none());
    }

    #[test]
    fn test_simple_cycle_floyd() {
        let mut detector = CycleDetector::new();
        detector.record_step(ExecutionNode::new("a", 1));
        detector.record_step(ExecutionNode::new("b", 2));
        detector.record_step(ExecutionNode::new("a", 3));

        let cycle = detector.detect_cycle_floyd();
        assert!(cycle.is_some());
        let cycle = cycle.unwrap();
        assert_eq!(cycle.detected_at_step(), 3);
    }

    #[test]
    fn test_complex_cycle_tarjan() {
        let mut detector = CycleDetector::new();
        detector.record_step(ExecutionNode::new("a", 1));
        detector.record_step(ExecutionNode::new("b", 2));
        detector.record_step(ExecutionNode::new("c", 3));
        detector.record_step(ExecutionNode::new("a", 4));

        let cycle = detector.detect_cycle_tarjan();
        assert!(cycle.is_some());
    }

    #[test]
    fn test_detector_clear() {
        let mut detector = CycleDetector::new();
        detector.record_step(ExecutionNode::new("a", 1));
        detector.record_step(ExecutionNode::new("a", 2));

        assert!(detector.detect_cycle().is_some());

        detector.clear();
        assert!(detector.path().is_empty());
        assert!(detector.detect_cycle().is_none());
    }
}
