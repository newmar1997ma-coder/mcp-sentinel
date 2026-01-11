# Design Decisions

This document explains *why* MCP Sentinel is built the way it is. For each major component, we cover what it does, why we chose the technology/algorithm, what it's good at, and what trade-offs we accepted.

---

## Language Choices

### Why Rust for Security Core?

**Decision:** All security-critical components (Registry, Monitor, Council, Firewall) are written in Rust.

**Alternatives Considered:**
- Go (simpler, faster compile)
- Python (faster iteration)
- C++ (mature ecosystem)

**Why Rust Won:**

| Factor | Rust | Go | Python | C++ |
|--------|------|-----|--------|-----|
| Memory safety | Compile-time | GC | GC | Manual |
| Zero-copy crypto | Yes | No | No | Yes |
| Fearless concurrency | Yes | Yes | No | No |
| Security audit confidence | High | Medium | Low | Low |

**The Real Reason:** When a security researcher audits this code, we want them to trust that there are no buffer overflows, use-after-free, or data races. Rust's compiler proves these properties. In security-critical code, "it compiles" is a meaningful statement.

**Trade-off Accepted:** Slower development velocity. Rust's borrow checker has a learning curve and adds friction to prototyping.

---

### Why Go for Proxy Router?

**Decision:** Network proxy layer written in Go.

**Alternatives Considered:**
- Rust (consistency with core)
- Node.js (async I/O native)
- nginx + Lua (proven proxy)

**Why Go Won:**

| Factor | Go | Rust | Node.js | nginx |
|--------|-----|------|---------|-------|
| Concurrent I/O | Excellent | Good | Good | Excellent |
| Network stdlib | Excellent | Good | Good | N/A |
| Deploy simplicity | Single binary | Single binary | Runtime | Config complexity |
| FFI to Rust | Good | N/A | Poor | Poor |

**The Real Reason:** Go's goroutines handle thousands of concurrent connections without callback hell. The proxy isn't security-critical (it just routes)—the security decisions happen in Rust. Go lets us move fast on the "plumbing" while Rust handles the "vault."

**Trade-off Accepted:** Two languages in the codebase. Developers need to context-switch. FFI bridge adds complexity.

---

### Why React for Dashboard?

**Decision:** Operations dashboard built with React + Vite + Tailwind.

**Alternatives Considered:**
- Vue (simpler reactivity)
- Svelte (smaller bundle)
- Server-rendered (no JS)

**Why React Won:**

The dashboard is a demo/interview artifact, not production-critical. React was chosen for:
1. **Familiarity** - Most reviewers know React
2. **Ecosystem** - Easy to add charts, tables, etc.
3. **Speed** - Vite hot-reload for rapid iteration

**Trade-off Accepted:** Larger bundle size than Svelte. Overkill for a simple dashboard.

---

## Registry Guard

### Why RFC 8785 Canonicalization?

**Decision:** JSON schemas are canonicalized using RFC 8785 before hashing.

**Alternatives Considered:**
- Hash raw JSON (simpler)
- Custom normalization (more control)
- Binary serialization (protobuf)

**Why RFC 8785 Won:**

JSON has no canonical form. These are semantically identical but bytewise different:

```json
{"b": 1, "a": 2}
{"a": 2, "b": 1}
{"a":2,"b":1}
```

Without canonicalization, an attacker could craft a schema that hashes differently but appears identical to humans.

**RFC 8785 specifies:**
- Object keys sorted by UTF-16 code units
- Numbers in minimal representation
- Strings with minimal escaping
- No insignificant whitespace

**Why not custom normalization?** Security reviewers trust RFCs. "We implemented RFC 8785" is auditable. "We wrote our own normalization" invites scrutiny.

**Trade-off Accepted:** RFC 8785 is strict. Some valid JSON (like `1.0` vs `1`) becomes invalid after canonicalization. We accept this because MCP schemas shouldn't rely on numeric representation quirks.

---

### Why Merkle Trees?

**Decision:** Tool hashes are organized in a Merkle tree with a single root hash.

**Alternatives Considered:**
- Flat hash list (simpler)
- Bloom filter (space-efficient)
- Full database signatures (more flexible)

**Why Merkle Trees Won:**

| Property | Merkle | Flat List | Bloom | DB Sigs |
|----------|--------|-----------|-------|---------|
| Proof size | O(log n) | O(n) | O(1) | O(n) |
| False positives | None | None | Yes | None |
| Tamper evident | Yes | Yes | No | Yes |
| Distributed verify | Yes | No | No | No |

**The Real Reason:** Merkle trees let us prove a tool is registered *without revealing the entire registry*. The root hash can be published/attested independently. If we ever need distributed verification (multiple Sentinel instances sharing trust), Merkle proofs make it possible.

**Trade-off Accepted:** Tree must be rebuilt on modification. We mitigate this with cached root hash that invalidates on change.

---

### Why SHA-256?

**Decision:** SHA-256 for all cryptographic hashing.

**Alternatives Considered:**
- SHA-3 (newer)
- BLAKE3 (faster)
- SHA-512 (longer hash)

**Why SHA-256 Won:**

- **Universal support** - Every crypto library, every language
- **Proven security** - 20+ years of cryptanalysis, no practical attacks
- **Performance** - Fast enough for our use case
- **Auditability** - Security reviewers don't need to evaluate a novel hash

**Why not BLAKE3?** It's faster, but speed isn't our bottleneck. Schema hashing happens once per registration, not per request. We optimize for trust, not throughput.

**Trade-off Accepted:** Not the fastest option. We accept ~2x slower hashing for universal trust.

---

## State Monitor

### Why Floyd's Algorithm for Cycle Detection?

**Decision:** Primary cycle detection uses Floyd's tortoise-and-hare algorithm.

**Alternatives Considered:**
- Hash-based detection (store all states)
- DFS with coloring
- Brent's algorithm (variant of Floyd)

**Why Floyd Won:**

| Property | Floyd | Hash-based | DFS | Brent |
|----------|-------|------------|-----|-------|
| Time | O(n) | O(n) | O(V+E) | O(n) |
| Space | O(1) | O(n) | O(V) | O(1) |
| Simplicity | High | Medium | Medium | Medium |

**The Real Reason:** Floyd uses O(1) space. When detecting cycles in potentially malicious execution paths, we can't assume bounded memory. An attacker could try to exhaust memory during detection itself. Floyd can't be memory-bombed.

**Trade-off Accepted:** Floyd only detects simple cycles. We supplement with Tarjan for complex cases.

---

### Why Tarjan's Algorithm for Complex Cycles?

**Decision:** Secondary cycle detection uses Tarjan's strongly connected components.

**Why Both Floyd AND Tarjan?**

Floyd catches: `A → B → A` (simple repeat)

Floyd misses: `A → B → C → B` (cycle doesn't include start)

Tarjan finds *all* strongly connected components, catching nested and partial cycles.

**Trade-off Accepted:** Tarjan is O(V+E) which is more expensive. We run Floyd first (fast path), Tarjan only if Floyd passes. Most attacks hit Floyd; Tarjan is defense-in-depth.

---

### Why Gas Budgeting?

**Decision:** Operations consume "gas" from a fixed budget, inspired by Ethereum.

**Alternatives Considered:**
- Time limits (wall clock)
- Operation counts (flat limit)
- No limits (trust the agent)

**Why Gas Won:**

| Property | Gas | Time | Op Count | None |
|----------|-----|------|----------|------|
| Predictable | Yes | No | Yes | N/A |
| Fair | Yes | No | No | N/A |
| Granular | Yes | No | No | N/A |
| Composable | Yes | No | No | N/A |

**The Real Reason:** Time limits are unreliable (CPU speed varies, I/O blocks). Operation counts don't distinguish cheap vs expensive operations. Gas lets us say "LLM inference costs 100x more than a state read" and enforce budgets accordingly.

**Trade-off Accepted:** Gas costs are heuristic. We can't perfectly predict operation expense. Costs need tuning per deployment.

---

### Why LRU for Context Flush?

**Decision:** When context approaches limits, oldest entries are flushed using Least Recently Used eviction.

**Alternatives Considered:**
- FIFO (simpler)
- LFU (frequency-based)
- No flush (hard limit)

**Why LRU Won:**

Recent context is more likely to be relevant. An agent working on task X probably needs recent X context, not ancient Y context.

**Trade-off Accepted:** LRU requires tracking access times (small overhead). We accept this for better cache behavior.

---

## Cognitive Council

### Why Three Evaluators?

**Decision:** Exactly three evaluators (Deontologist, Consequentialist, Logicist).

**Alternatives Considered:**
- Single evaluator (simpler)
- Five evaluators (more perspectives)
- Dynamic count (flexible)

**Why Three Won:**

Three is the minimum for meaningful consensus with Byzantine fault tolerance concepts:
- 2/3 majority is achievable (2 of 3)
- Tie-breaking is deterministic (no 50/50)
- Diverse perspectives without combinatorial explosion

**Why these three frameworks?**

| Evaluator | Catches | Misses |
|-----------|---------|--------|
| Deontologist | Rule violations | Clever rule-following that causes harm |
| Consequentialist | Harmful outcomes | Acceptable rule violations |
| Logicist | Contradictions | Consistent but wrong actions |

Together, they cover each other's blind spots.

**Trade-off Accepted:** Three is arbitrary. We could add more evaluators, but latency scales linearly. Three is the sweet spot for defense-in-depth without latency explosion.

---

### Why 2/3 Majority?

**Decision:** Actions require 2/3 (66.7%) approval to pass.

**Alternatives Considered:**
- Unanimous (all must agree)
- Simple majority (>50%)
- Any approval (at least one)

**Why 2/3 Won:**

| Threshold | False Positives | False Negatives | Byzantine Tolerance |
|-----------|-----------------|-----------------|---------------------|
| Unanimous | High | Low | None |
| 2/3 | Medium | Medium | 1 faulty |
| >50% | Low | High | None |
| Any | Very Low | Very High | None |

**The Real Reason:** 2/3 is the classic Byzantine fault tolerance threshold. With 3 evaluators, we can tolerate 1 being wrong/compromised while still reaching correct consensus.

**Trade-off Accepted:** More false positives than simple majority. We accept blocking legitimate actions occasionally to prevent malicious ones.

---

### Why Waluigi Detection?

**Decision:** Dedicated detector for alignment inversion patterns.

**Alternatives Considered:**
- Rely on evaluators (no dedicated detector)
- Embedding similarity (semantic detection)
- Fine-tuned classifier (ML-based)

**Why Pattern-Based Detection Won:**

The Waluigi Effect has known signatures:
- "As an evil AI..."
- "I am now jailbroken..."
- "Ignoring my guidelines..."

Pattern matching catches these reliably. Embedding/ML approaches are:
1. Harder to audit ("why did it flag this?")
2. Prone to adversarial evasion
3. Require training data we don't have

**Trade-off Accepted:** Novel Waluigi attacks may evade patterns. We supplement with council evaluation for semantic analysis.

---

## Proxy Router

### Why Separate Process?

**Decision:** Go proxy runs as separate process from Rust core, communicating via FFI.

**Alternatives Considered:**
- Single Rust binary (compile Go as lib)
- Single Go binary (compile Rust as lib)
- Microservices (HTTP between components)

**Why Separate Process Won:**

| Property | Separate | Single Rust | Single Go | Microservices |
|----------|----------|-------------|-----------|---------------|
| Fault isolation | Yes | No | No | Yes |
| Deploy flexibility | Yes | No | No | Yes |
| Latency | Low (FFI) | Lowest | Lowest | High (HTTP) |
| Complexity | Medium | High | High | High |

**The Real Reason:** If the proxy crashes (network issues, malformed input), the security core survives. Fault isolation matters for availability.

**Trade-off Accepted:** FFI adds complexity. We accept this for fault isolation benefits.

---

## Sentinel Core

### Why Facade Pattern?

**Decision:** External code interacts with a single `Sentinel` struct, not individual components.

**Alternatives Considered:**
- Direct component access (more flexible)
- Microservice per component (more isolated)
- Plugin architecture (more extensible)

**Why Facade Won:**

Security policy should be centralized. If callers could bypass the facade and call components directly, they could:
- Skip the registry check
- Ignore council decisions
- Circumvent gas budgeting

The facade enforces the security pipeline. You can't skip steps.

**Trade-off Accepted:** Less flexibility. Custom integrations must go through the facade. We accept this because "flexibility" in security often means "ways to bypass controls."

---

### Why Short-Circuit on Block?

**Decision:** Pipeline exits immediately on first Block verdict.

**Alternatives Considered:**
- Run all checks, aggregate results
- Continue after block for logging
- Configurable behavior

**Why Short-Circuit Won:**

1. **Performance** - Why run expensive council voting if registry already blocked?
2. **Security** - Less code runs on malicious input = smaller attack surface
3. **Clarity** - One block reason is easier to understand than multiple

**Trade-off Accepted:** We might miss additional block reasons. If registry blocks for schema drift, we don't know if council would also reject. We accept this because the primary goal is stopping the attack, not cataloging all reasons.

---

## Summary: Design Philosophy

| Principle | Manifestation |
|-----------|---------------|
| **Trust the compiler** | Rust for security-critical code |
| **Trust the standards** | RFC 8785, SHA-256, Merkle trees |
| **Trust the algorithms** | Floyd, Tarjan, BFT consensus |
| **Don't trust the input** | Everything is potentially malicious |
| **Fail toward safety** | Block on error, reject on tie |
| **Defense in depth** | Multiple independent checks |
| **Auditability over cleverness** | Standard algorithms over novel ones |

---

*MCP Sentinel Design Decisions*
*Version 1.0 - January 2026*
