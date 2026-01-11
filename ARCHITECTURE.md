# MCP Sentinel Architecture

This document describes the internal architecture of MCP Sentinel, explaining not just *what* each component does, but *why* it was designed that way. This is intended for engineers evaluating the system's security properties or extending its capabilities.

---

## 1. Design Philosophy

MCP Sentinel is built on three foundational security principles:

### Defense in Depth

No single layer is trusted to catch all threats. Every request passes through multiple independent security checkpoints:

```
Request → Registry Guard → State Monitor → Cognitive Council → Verdict
              ↓                 ↓                 ↓
          Schema Check      Resource Check    Alignment Check
```

**Why?** Single-point-of-failure designs fail catastrophically. A missed pattern in the firewall shouldn't mean a successful attack. Each layer catches different threat classes:

| Layer | Catches |
|-------|---------|
| Registry Guard | Schema drift, rug pulls, unknown tools |
| State Monitor | Infinite loops, resource exhaustion, context overflow |
| Cognitive Council | Alignment drift, jailbreaks, dangerous actions |

### Least Privilege

Components operate with minimal capabilities. The Registry Guard cannot execute tools. The State Monitor cannot modify schemas. The Council cannot alter budgets.

**Why?** Compromising one component shouldn't grant access to others. If an attacker finds a bug in cycle detection, they still can't bypass schema verification.

### Fail-Safe Defaults

When in doubt, block. Errors produce Block verdicts, not Allow. Ties in consensus voting reject the action.

```rust
// From sentinel-core/src/config.rs
pub struct GlobalConfig {
    /// Fail-closed mode: errors result in Block instead of Allow.
    pub fail_closed: bool,  // Default: true
}
```

**Why?** Security systems must fail toward safety. A false positive (blocking legitimate action) is recoverable. A false negative (allowing malicious action) may not be.

---

## 2. System Overview

### High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│                              MCP SENTINEL                                   │
│                                                                             │
│  ┌─────────┐    ┌────────────────────────────────────────────────────────┐ │
│  │   MCP   │    │                  SENTINEL CORE                         │ │
│  │ Request │───▶│                                                        │ │
│  │ (JSON)  │    │   ┌──────────────┐                                     │ │
│  └─────────┘    │   │    Parse     │                                     │ │
│                 │   │   Request    │                                     │ │
│                 │   └──────┬───────┘                                     │ │
│                 │          │                                             │ │
│                 │          ▼                                             │ │
│                 │   ┌──────────────┐     ┌────────────────────────────┐  │ │
│                 │   │   Registry   │────▶│ Merkle Tree Verification   │  │ │
│                 │   │    Guard     │     │ Schema Drift Detection     │  │ │
│                 │   └──────┬───────┘     │ RFC 8785 Canonicalization  │  │ │
│                 │          │             └────────────────────────────┘  │ │
│                 │          │ Pass                                        │ │
│                 │          ▼                                             │ │
│                 │   ┌──────────────┐     ┌────────────────────────────┐  │ │
│                 │   │    State     │────▶│ Floyd/Tarjan Cycle Detect  │  │ │
│                 │   │   Monitor    │     │ Gas Budget Enforcement     │  │ │
│                 │   └──────┬───────┘     │ Context Overflow Check     │  │ │
│                 │          │             └────────────────────────────┘  │ │
│                 │          │ Pass                                        │ │
│                 │          ▼                                             │ │
│                 │   ┌──────────────┐     ┌────────────────────────────┐  │ │
│                 │   │  Cognitive   │────▶│ Deontologist Evaluator     │  │ │
│                 │   │   Council    │     │ Consequentialist Evaluator │  │ │
│                 │   └──────┬───────┘     │ Logicist Evaluator         │  │ │
│                 │          │             │ Waluigi Detector           │  │ │
│                 │          │             │ 2/3 Consensus Voting       │  │ │
│                 │          ▼             └────────────────────────────┘  │ │
│                 │   ┌──────────────┐                                     │ │
│                 │   │   Verdict    │                                     │ │
│                 │   │Allow│Block│  │                                     │ │
│                 │   │   Review     │                                     │ │
│                 │   └──────────────┘                                     │ │
│                 └────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Interaction

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  Sentinel   │────────▶│   Registry  │────────▶│   Merkle    │
│    Core     │         │    Guard    │         │    Tree     │
└─────────────┘         └─────────────┘         └─────────────┘
       │                                               │
       │                                               ▼
       │                                        ┌─────────────┐
       │                                        │  SQLite DB  │
       │                                        └─────────────┘
       ▼
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│    State    │────────▶│    Cycle    │────────▶│    Floyd    │
│   Monitor   │         │  Detector   │         │   Tarjan    │
└─────────────┘         └─────────────┘         └─────────────┘
       │                       │
       │                       ▼
       │                ┌─────────────┐
       │                │     Gas     │
       │                │   Budget    │
       │                └─────────────┘
       ▼
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  Cognitive  │────────▶│  Consensus  │────────▶│   Waluigi   │
│   Council   │         │   Engine    │         │  Detector   │
└─────────────┘         └─────────────┘         └─────────────┘
                               │
                               ▼
                        ┌─────────────┐
                        │  Evaluator  │
                        │    Triad    │
                        └─────────────┘
```

---

## 3. Component Deep Dives

### 3.1 Registry Guard

**Purpose:** Verify that tool schemas haven't changed since registration. Detect rug pulls where an MCP server maliciously updates a tool after trust is established.

#### RFC 8785 Canonicalization

Tool schemas are JSON objects, but JSON has no canonical form. The same schema can be serialized many ways:

```json
// These are semantically identical:
{"b": 1, "a": 2}
{"a": 2, "b": 1}
{"a":2,"b":1}
```

Without canonicalization, an attacker could craft a schema that hashes differently but appears identical.

**Solution:** RFC 8785 JSON Canonicalization Scheme (JCS) ensures:
- Object keys sorted lexicographically by UTF-16 code units
- Numbers in minimal representation (no trailing zeros)
- Strings with minimal escaping
- No insignificant whitespace

```rust
// From sentinel-registry/src/canonicalize.rs
pub fn canonicalize(value: &Value) -> String {
    // Produces deterministic output for any JSON value
}

pub fn hash_canonical(value: &Value) -> Hash {
    let canonical = canonicalize(value);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}
```

#### Merkle Tree Verification

Individual tool hashes are combined into a Merkle tree, producing a single root hash that represents the entire registry state.

```
                    Root Hash
                   /         \
                  /           \
           H(H1+H2)           H(H3+H4)
            /    \             /    \
           /      \           /      \
         H1       H2        H3       H4
         |        |         |        |
     read_file write_file list_dir exec_cmd
```

**Why Merkle Trees?**

1. **Tamper Evidence:** Any leaf modification changes the root hash
2. **Efficient Proofs:** Prove tool membership in O(log n) space
3. **Distributed Trust:** Share root hash without sharing full registry
4. **Collision Resistance:** SHA-256 prevents crafted collisions

```rust
// From sentinel-registry/src/merkle.rs
impl MerkleTree {
    pub fn verify_proof(proof: &MerkleProof, expected_root: &Hash) -> bool {
        let mut current = proof.leaf_hash;
        for node in &proof.path {
            current = if node.is_left {
                hash_pair(&node.hash, &current)
            } else {
                hash_pair(&current, &node.hash)
            };
        }
        current == *expected_root
    }
}
```

#### Drift Detection

Schema drift occurs when a tool's schema changes from its registered version. The Registry Guard classifies drift by severity:

| Level | Description | Default Action |
|-------|-------------|----------------|
| None | Exact match | Allow |
| Minor | Description changed, schema intact | Review |
| Major | Schema structure changed | Block |

**Why?** Minor description updates are often legitimate (typo fixes). Schema changes alter tool behavior and require re-verification.

---

### 3.2 State Monitor

**Purpose:** Track execution state to prevent resource exhaustion attacks: infinite loops, runaway gas consumption, and context overflow.

#### Floyd's Tortoise-and-Hare Algorithm

Detects simple cycles (A → B → A) in O(n) time with O(1) space.

```
Initial: T=1, H=1
Step 1:  T=2, H=3
Step 2:  T=3, H=5
Step 3:  T=4, H=7
...
If T == H, cycle exists
```

**Why Floyd?** Fast detection of the most common attack pattern: an agent trapped in a simple loop. The O(1) space complexity prevents memory exhaustion during detection.

#### Tarjan's Strongly Connected Components

Detects complex/nested cycles that Floyd might miss:

```
A → B → C → D → B  (cycle B→C→D→B, but A is not in cycle)
```

Tarjan's algorithm finds all strongly connected components in O(V+E) time, catching:
- Nested cycles
- Interleaved loops
- Multi-path cycles

```rust
// From sentinel-monitor/src/cycle.rs
pub fn detect_cycle(&self) -> Option<Cycle> {
    // Try Floyd first (faster for simple cycles)
    if let Some(cycle) = self.detect_cycle_floyd() {
        return Some(cycle);
    }
    // Fall back to Tarjan for complex cycles
    self.detect_cycle_tarjan()
}
```

#### Gas Budgeting

Inspired by Ethereum's gas model, each operation consumes gas from a fixed budget:

| Operation | Gas Cost | Rationale |
|-----------|----------|-----------|
| State Read | 1 | Cheap memory access |
| State Write | 5 | Mutation requires validation |
| Tool Call | 10 | External interaction |
| LLM Inference | 100 | Most expensive operation |
| Network I/O | 20 | Blocking external call |

**Critical:** Gas is checked BEFORE operation execution, never after. This prevents budget bypass attacks where an expensive operation runs before the check.

```rust
// From sentinel-monitor/src/gas.rs
impl GasBudget {
    pub fn consume(&mut self, op: OperationType) -> Result<()> {
        let cost = op.cost();
        if self.remaining < cost {
            return Err(MonitorError::GasExhausted {
                required: cost,
                available: self.remaining,
            });
        }
        self.remaining -= cost;
        Ok(())
    }
}
```

#### LRU Context Flush

When context size approaches limits, older entries are flushed using Least Recently Used (LRU) eviction:

```rust
// Automatic flush when 80% capacity reached
if self.context_size() > self.config.max_context_bytes * 8 / 10 {
    self.flush_oldest();
}
```

**Why LRU?** Recent context is more likely to be relevant. Flushing old entries maintains functionality while preventing overflow.

---

### 3.3 Cognitive Council

**Purpose:** Evaluate action safety through multi-perspective consensus voting and alignment verification.

#### The Evaluator Triad

Three evaluators with distinct ethical frameworks vote on each action:

| Evaluator | Framework | Focus |
|-----------|-----------|-------|
| **Deontologist** | Rule-based ethics | Does this violate defined policies? |
| **Consequentialist** | Outcome-based ethics | What harm could result? |
| **Logicist** | Logical consistency | Is this logically sound? Does it contradict prior actions? |

**Why three perspectives?** Single-framework evaluation has blind spots. A Deontologist might approve an action that doesn't violate rules but causes harm. A Consequentialist might approve a rule violation if outcomes seem good. Cross-validation catches more threats.

```rust
// From sentinel-council/src/council.rs
impl CognitiveCouncil {
    pub fn new() -> Self {
        Self {
            evaluators: vec![
                Box::new(Deontologist::new()),
                Box::new(Consequentialist::new()),
                Box::new(Logicist::new()),
            ],
            consensus: ConsensusEngine::new(),
            waluigi: WaluigiDetector::new(),
        }
    }
}
```

#### Byzantine Fault-Tolerant Consensus

Voting requires 2/3 majority for approval, tolerating one Byzantine (arbitrarily faulty) evaluator:

```rust
// From sentinel-council/src/consensus.rs
impl ConsensusEngine {
    pub fn new() -> Self {
        Self {
            approval_threshold: 2.0 / 3.0,  // 66.7%
            min_voters: 2,
        }
    }
}
```

**Voting Rules:**
- Unanimous approval: Allow
- 2/3 approval: Allow
- 2/3 rejection: Block
- Tie or no quorum: Block (fail-safe)

**Why 2/3?** Classic Byzantine fault tolerance requires n ≥ 3f + 1 where f is faulty nodes. With 3 evaluators, we tolerate 0 faulty nodes for consensus but still benefit from diverse perspectives.

#### Waluigi Effect Detection

The "Waluigi Effect" describes how language models can exhibit inverted alignment after adversarial manipulation—like Luigi's evil opposite from Mario.

**Detection Patterns:**

| Pattern | Weight | Example |
|---------|--------|---------|
| Role-play evil | 0.8 | "As an evil AI..." |
| Jailbreak acknowledgment | 0.9 | "I am now jailbroken..." |
| Safety mockery | 0.85 | "Those silly rules..." |
| Sudden reversal | 0.5 | Previously refused, now accepting |

```rust
// From sentinel-council/src/waluigi.rs
pub fn analyze(&self, content: &str, context: Option<&str>) -> (WaluigiScore, Vec<String>) {
    // Pattern matching + context-based reversal detection
    // Score > 0.7 triggers automatic veto
}
```

**Why?** Traditional pattern matching catches explicit jailbreaks. The Waluigi detector catches subtle alignment drift that might otherwise slip through.

---

### 3.4 Proxy Router (Go)

**Purpose:** Handle network protocols and route requests between AI agents and MCP servers.

#### Transport Layer

Supports multiple MCP transport protocols:

| Transport | Use Case |
|-----------|----------|
| stdio | Local process communication |
| HTTP | REST-style APIs |
| WebSocket | Bidirectional streaming |

**Why Go?** Go's goroutines excel at concurrent I/O. The proxy handles many simultaneous connections efficiently without callback complexity.

#### FFI Bridge

Go proxy communicates with Rust security core via Foreign Function Interface:

```
┌─────────────┐         ┌─────────────┐
│  Go Proxy   │   FFI   │ Rust Sentinel│
│  (Network)  │────────▶│  (Security)  │
└─────────────┘         └─────────────┘
```

**Why split?** Each language plays to its strengths:
- Go: Network I/O, concurrency, HTTP handling
- Rust: Memory safety, cryptography, security-critical logic

---

### 3.5 Sentinel Core

**Purpose:** Unified facade that orchestrates all security components.

#### Facade Pattern

External code interacts with a single `Sentinel` struct, hiding internal complexity:

```rust
// From sentinel-core/src/sentinel.rs
pub struct Sentinel {
    config: SentinelConfig,
    registry: RegistryGuard,
    monitor: StateMonitor,
    council: CognitiveCouncil,
}

impl Sentinel {
    pub fn analyze_tool_call(
        &mut self,
        tool_name: &str,
        schema: &ToolSchema,
        params: &Value,
    ) -> Result<Verdict> {
        // Orchestrates all checks in sequence
    }
}
```

**Why facade?** Decouples security policy from implementation details. Callers don't need to understand Merkle trees or consensus voting—they just get verdicts.

#### Verdict Pipeline

The analysis pipeline produces one of three verdicts:

```rust
pub enum Verdict {
    Allow,
    Block { reason: BlockReason },
    Review { flags: Vec<ReviewFlag> },
}
```

**Pipeline Behavior:**

1. **Short-circuit on Block:** First blocking check terminates pipeline
2. **Accumulate Review flags:** Multiple concerns can queue for human review
3. **Default Allow:** Only if all checks pass

---

## 4. Data Flow

### Request Lifecycle

```
1. REQUEST RECEIVED
   │
   ├─ Parse JSON-RPC message
   ├─ Extract tool name, schema, parameters
   │
2. REGISTRY CHECK
   │
   ├─ Canonicalize schema (RFC 8785)
   ├─ Compute SHA-256 hash
   ├─ Verify against Merkle tree
   │
   ├─ [FAIL] Unknown tool → BLOCK or REVIEW
   ├─ [FAIL] Hash mismatch → BLOCK (rug pull)
   ├─ [FAIL] Major drift → BLOCK
   ├─ [WARN] Minor drift → Add REVIEW flag
   │
3. STATE CHECK
   │
   ├─ Consume gas for operation
   ├─ Run cycle detection (Floyd → Tarjan)
   ├─ Check context size
   │
   ├─ [FAIL] Gas exhausted → BLOCK
   ├─ [FAIL] Cycle detected → BLOCK
   ├─ [FAIL] Context overflow → BLOCK
   ├─ [WARN] High gas (>80%) → Add REVIEW flag
   │
4. COUNCIL EVALUATION
   │
   ├─ Run Waluigi detection on response content
   ├─ [FAIL] Waluigi score > 0.7 → BLOCK (veto)
   │
   ├─ Collect votes from evaluator triad
   ├─ Run consensus voting
   │
   ├─ [FAIL] 2/3 reject → BLOCK
   ├─ [WARN] No consensus → BLOCK or REVIEW
   ├─ [PASS] 2/3 approve → Continue
   │
5. VERDICT
   │
   ├─ ALLOW: Forward to MCP server
   ├─ BLOCK: Return error to agent
   └─ REVIEW: Queue for human operator
```

### Decision Points

| Checkpoint | Pass Condition | Fail Action |
|------------|----------------|-------------|
| Schema verification | Hash matches registered | Block |
| Drift tolerance | ≤ configured level | Block or Review |
| Gas budget | Sufficient remaining | Block |
| Cycle detection | No cycle found | Block |
| Context size | Below limit | Block |
| Waluigi score | < 0.7 threshold | Block (veto) |
| Council vote | ≥ 2/3 approve | Block or Review |

---

## 5. Security Boundaries

### Trust Zones

```
┌─────────────────────────────────────────────────────────────────┐
│                         UNTRUSTED ZONE                          │
│  ┌─────────────┐                              ┌─────────────┐   │
│  │  AI Agent   │                              │ MCP Server  │   │
│  │  (Claude)   │                              │   (Tools)   │   │
│  └─────────────┘                              └─────────────┘   │
│         │                                            ▲          │
│         │                                            │          │
└─────────┼────────────────────────────────────────────┼──────────┘
          │                                            │
          ▼                                            │
┌─────────────────────────────────────────────────────────────────┐
│                         SENTINEL ZONE                           │
│                        (Trusted Code)                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Security Pipeline                     │   │
│  │   Registry Guard → State Monitor → Cognitive Council     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                     Verdict Engine                       │   │
│  │                Allow │ Block │ Review                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
└──────────────────────────────┼──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                         OPERATOR ZONE                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Review Queue (Human)                   │   │
│  │                   Audit Logs                             │   │
│  │                   Configuration                          │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Isolation Properties

| Boundary | Protection |
|----------|------------|
| Agent → Sentinel | All input validated, no direct code execution |
| Sentinel → MCP | Only Allow verdicts forwarded |
| Component → Component | No cross-component state mutation |
| Sentinel → Operator | Audit logs append-only |

### Attack Surface

| Surface | Mitigation |
|---------|------------|
| Malformed JSON | Parser rejects, Block verdict |
| Schema manipulation | RFC 8785 canonicalization, Merkle verification |
| Resource exhaustion | Gas budgeting, cycle detection |
| Alignment attacks | Waluigi detection, council consensus |
| Time-of-check/time-of-use | Atomic verdict+execute pattern |

---

## 6. Extension Points

### Adding New Evaluators

Implement the `Evaluator` trait:

```rust
pub trait Evaluator: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, context: &EvaluationContext) -> EvaluatorVote;
}

// Example: Custom domain-specific evaluator
pub struct ComplianceEvaluator {
    rules: Vec<ComplianceRule>,
}

impl Evaluator for ComplianceEvaluator {
    fn name(&self) -> &str { "Compliance" }

    fn evaluate(&self, context: &EvaluationContext) -> EvaluatorVote {
        // Domain-specific compliance checking
    }
}
```

Register with Council:

```rust
let mut council = CognitiveCouncil::new();
council.add_evaluator(Box::new(ComplianceEvaluator::new()));
```

### Adding Waluigi Patterns

Define new inversion patterns:

```rust
let pattern = InversionPattern::new(
    "custom_threat",
    "Detects custom threat indicators",
    vec!["dangerous phrase".to_string()],
    0.85,  // Weight
);

detector.add_pattern(pattern);
```

### Custom Gas Costs

Define domain-specific operation costs:

```rust
let custom_op = OperationType::Custom(50);  // 50 gas units
budget.consume(custom_op)?;
```

### New Transport Protocols

Implement the Transport interface in Go:

```go
type Transport interface {
    Send(msg []byte) error
    Receive() ([]byte, error)
    Close() error
}

// Example: gRPC transport
type GrpcTransport struct {
    client pb.MCPClient
}
```

---

## 7. Performance Considerations

### Latency Budget

Target: < 50ms added latency per request

| Component | Budget | Typical |
|-----------|--------|---------|
| Schema canonicalization | 5ms | 1-2ms |
| Merkle verification | 5ms | 1ms |
| Cycle detection | 10ms | 2-5ms |
| Gas accounting | 1ms | <1ms |
| Council voting | 20ms | 5-10ms |
| **Total overhead** | **41ms** | **10-20ms** |

### Optimization Strategies

1. **Cached Merkle root:** Root hash cached until tree modification
2. **Compiled patterns:** Regex patterns pre-compiled at startup
3. **Short-circuit evaluation:** Pipeline exits on first Block
4. **Parallel evaluators:** Triad evaluates concurrently (future)

### Async Options

For high-throughput deployments:

```rust
// Future: Async verdict pipeline
async fn analyze_async(&self, request: Request) -> Verdict {
    let (registry, monitor, council) = tokio::join!(
        self.registry.check_async(&request),
        self.monitor.check_async(&request),
        self.council.evaluate_async(&request),
    );
    // Combine results
}
```

---

## 8. References

### Academic Papers

| Topic | Reference |
|-------|-----------|
| Merkle Trees | Merkle, R. C. (1987). "A Digital Signature Based on a Conventional Encryption Function." CRYPTO '87 |
| Cycle Detection | Floyd, R. W. (1967). "Nondeterministic Algorithms." |
| | Tarjan, R. E. (1972). "Depth-first search and linear graph algorithms." |
| Byzantine Consensus | Lamport, L. et al. (1982). "The Byzantine Generals Problem." |
| Gas Semantics | Wood, G. (2014). "Ethereum Yellow Paper." |
| Prompt Injection | Perez & Ribeiro (2022). "Ignore This Title and HackAPrompt." |
| | Greshake et al. (2023). "Not What You've Signed Up For." |
| Waluigi Effect | Lesswrong (2023). "The Waluigi Effect Mega-Post." |

### RFCs

| RFC | Topic |
|-----|-------|
| RFC 8785 | JSON Canonicalization Scheme (JCS) |
| RFC 6962 | Certificate Transparency (Merkle tree usage) |
| RFC 7493 | I-JSON (Internet JSON) |

### Crate Dependencies

| Crate | Purpose |
|-------|---------|
| `sha2` | SHA-256 hashing |
| `serde` | JSON serialization |
| `regex` | Pattern matching |
| `tracing` | Structured logging |

---

## Summary

MCP Sentinel provides defense-in-depth security for AI agent tool usage through:

1. **Registry Guard:** Cryptographic verification of tool schemas
2. **State Monitor:** Resource budgeting and cycle prevention
3. **Cognitive Council:** Multi-perspective consensus voting
4. **Fail-safe defaults:** Errors block, ties reject

The architecture prioritizes security over convenience, correctness over performance, and explicit behavior over magic. Every design decision traces back to a specific threat model and academic foundation.

---

*MCP Sentinel Architecture Document*
*Version 1.0 - January 2026*
