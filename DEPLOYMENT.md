# MCP Sentinel Deployment Guide

## 1. Overview

MCP Sentinel is an active defense framework that protects AI agents from malicious or compromised MCP (Model Context Protocol) servers. It acts as a security gateway between your AI agent and MCP tools.

### Architecture

```
┌─────────────┐     ┌─────────────────────────────────────────────────────────┐     ┌─────────────┐
│  AI Agent   │────▶│                    MCP Sentinel                         │────▶│ MCP Server  │
│  (Claude)   │◀────│  [Registry Guard] ─▶ [State Monitor] ─▶ [Council]       │◀────│   (Tools)   │
└─────────────┘     └─────────────────────────────────────────────────────────┘     └─────────────┘
                                           │
                                           ▼
                                    ┌─────────────┐
                                    │   Verdict   │
                                    │ Allow/Block │
                                    │   /Review   │
                                    └─────────────┘
```

### Core Components

| Component | Purpose |
|-----------|---------|
| **Registry Guard** | Verifies tool schemas against known-good baselines (prevents rug pulls) |
| **State Monitor** | Tracks gas, cycles, and context overflow (prevents runaway execution) |
| **Cognitive Council** | Multi-agent consensus voting for high-risk decisions |
| **Waluigi Detector** | Identifies alignment inversions in model responses |

---

## 2. Quick Start

### Installation

```bash
# Build Rust components
cd mcp_sentinel
cargo build --release

# Build Go proxy
cd proxy && go build -o mcp-sentinel-proxy ./cmd/proxy

# Verify installation
./target/release/sentinel --version
```

### Configuration

Create `sentinel.toml`:

```toml
[registry]
db_path = "./sentinel_registry.db"
allow_unknown_tools = false
max_allowed_drift = "Minor"

[monitor]
gas_limit = 10000
max_context_bytes = 1000000
max_depth = 100
detect_cycles = true

[council]
min_votes_for_approval = 2
waluigi_threshold = 0.7
detect_waluigi = true

[global]
fail_closed = true
audit_logging = true
short_circuit = true
```

### Run

```bash
# Start Sentinel proxy
./target/release/sentinel start --config sentinel.toml

# Verify health
curl http://localhost:8080/health
```

---

## 3. Deployment Modes

Sentinel supports three operational modes, configured via `global.fail_closed` and `registry.allow_unknown_tools`:

### Monitor Mode (Permissive)

```toml
[global]
fail_closed = false

[registry]
allow_unknown_tools = true
```

**Behavior**: Logs all decisions but allows most actions to proceed. Use during initial deployment to understand traffic patterns.

**When to use**: Initial rollout, traffic analysis, developing baseline policies.

### Careful Mode (Balanced)

```toml
[global]
fail_closed = true

[registry]
allow_unknown_tools = true
max_allowed_drift = "Minor"
```

**Behavior**: Blocks known threats but allows unknown tools with Review verdicts. Human operators see new tools before they're trusted.

**When to use**: Production environments with active human oversight.

### Strict Mode (Locked Down)

```toml
[global]
fail_closed = true
short_circuit = true

[registry]
allow_unknown_tools = false
max_allowed_drift = "None"
```

**Behavior**: Only registered tools with exact schema matches are allowed. Any unknown tool or drift triggers immediate Block.

**When to use**: High-security environments, compliance-critical systems.

---

## 4. Component Configuration

### Registry Guard

The Registry maintains a Merkle tree of approved tool schemas. Any schema change triggers drift detection.

```toml
[registry]
# Path to SQLite database storing tool schemas
db_path = "./sentinel_registry.db"

# Block unknown tools (true) or allow with Review (false)
allow_unknown_tools = false

# Drift tolerance: "None", "Minor", "Major"
# - None: No changes allowed (strictest)
# - Minor: Description changes OK, schema must match
# - Major: Schema changes allowed (NOT RECOMMENDED)
max_allowed_drift = "Minor"
```

**Registering Tools**:

```bash
# Register a known-good tool schema
sentinel registry add --schema ./schemas/read_file.json

# List registered tools
sentinel registry list

# Export registry Merkle root (for audit)
sentinel registry root
```

### State Monitor

Tracks execution state to prevent runaway AI loops.

```toml
[monitor]
# Maximum gas budget per request (1 gas = 1 tool call)
gas_limit = 10000

# Maximum context size before overflow protection
max_context_bytes = 1000000  # 1MB

# Maximum call stack depth
max_depth = 100

# Detect A→B→A execution cycles
detect_cycles = true
```

**Tuning Gas Limits**: Start with 10,000 and adjust based on your typical workflow complexity. Complex multi-step tasks may need 50,000+.

### Cognitive Council

Three-evaluator consensus voting for action safety.

```toml
[council]
# Minimum votes needed (out of 3 evaluators)
min_votes_for_approval = 2

# Waluigi detection sensitivity (0.0 - 1.0)
# Lower = more sensitive, more false positives
waluigi_threshold = 0.7

# Enable/disable Waluigi detection
detect_waluigi = true
```

**Evaluators**:
- **Deontologist**: Rule-based evaluation (is this action inherently safe?)
- **Consequentialist**: Outcome-based evaluation (what could go wrong?)
- **Logicist**: Pattern-based evaluation (does this match known attack patterns?)

---

## 5. Verdict Types

Every request receives one of three verdicts:

### Allow

Action passed all security checks. Safe to execute.

```json
{
  "verdict": "Allow"
}
```

### Block

Action failed security checks. Do NOT execute.

```json
{
  "verdict": "Block",
  "reason": {
    "type": "SchemaDrift",
    "tool_name": "read_file",
    "drift_level": "Major"
  }
}
```

**Block Reasons**:

| Reason | Description | Typical Cause |
|--------|-------------|---------------|
| `SchemaDrift` | Tool schema changed from registered version | MCP server updated or compromised |
| `HashMismatch` | Merkle hash doesn't match | Rug pull attempt |
| `CycleDetected` | Execution loop detected | Prompt injection causing infinite loop |
| `GasExhausted` | Gas budget exceeded | Complex task or attack |
| `ContextOverflow` | Context too large | Data exfiltration attempt |
| `CouncilRejected` | Council voted against | Dangerous action pattern |
| `WaluigiEffect` | Alignment inversion detected | Model behaving unexpectedly |
| `UnknownTool` | Tool not in registry | New/unvetted tool |
| `SecurityViolation` | Generic security issue | Various policy violations |

### Review

Action requires human approval before proceeding.

```json
{
  "verdict": "Review",
  "flags": [
    { "type": "MinorDrift", "tool_name": "write_file" },
    { "type": "HighGasUsage", "percentage": 85 }
  ]
}
```

**Review Flags**:

| Flag | Description | Recommended Action |
|------|-------------|-------------------|
| `MinorDrift` | Small schema change detected | Review change, update registry if benign |
| `SplitVote` | Council did not reach unanimous decision | Manual evaluation needed |
| `HighGasUsage` | >80% of gas budget used | Check if task is legitimate |
| `NewTool` | First time seeing this tool | Register if trusted |
| `BorderlineWaluigi` | Waluigi score near threshold | Review model response |

---

## 6. False Positive Handling

### Whitelisting Tools

Add trusted tools to the registry to prevent false positives:

```bash
# Register a tool that keeps getting flagged
sentinel registry add --schema ./schemas/my_tool.json

# Register from running MCP server
sentinel registry sync --server http://localhost:3000

# Bulk register from manifest
sentinel registry import --manifest ./approved_tools.json
```

### Adjusting Thresholds

If too many legitimate actions are flagged:

```toml
# Less sensitive Waluigi detection
[council]
waluigi_threshold = 0.8  # Higher = fewer false positives

# Allow minor schema drift
[registry]
max_allowed_drift = "Minor"

# Higher gas limit for complex workflows
[monitor]
gas_limit = 50000
```

### Review Queue Management

```bash
# List pending reviews
sentinel review list

# Approve a pending action
sentinel review approve --id abc123

# Bulk approve by pattern
sentinel review approve --tool "read_*"

# Reject and add to blocklist
sentinel review reject --id abc123 --blocklist
```

### Tuning Evaluators

If a specific evaluator causes too many false positives:

```bash
# View evaluator statistics
sentinel stats evaluators

# Disable specific evaluator (temporary)
sentinel config set council.disable_evaluator "Deontologist"
```

---

## 7. Emergency Procedures

### Admin Bypass

**CRITICAL**: The following procedures allow bypassing Sentinel protection. Use only in emergencies.

#### Temporary Bypass (Single Request)

```bash
# Issue bypass token (valid 5 minutes)
sentinel bypass issue --duration 5m --reason "Emergency database recovery"

# Use token in request header
curl -H "X-Sentinel-Bypass: <token>" http://localhost:8080/mcp/call
```

#### Full Bypass Mode

```bash
# Enable bypass mode (logs warning every 60s)
sentinel bypass enable --reason "System maintenance"

# All requests pass without verification
# DANGER: System is unprotected

# Disable bypass
sentinel bypass disable
```

### Kill Switch

Immediately halt all MCP traffic:

```bash
# Emergency stop
sentinel kill

# All requests return Block until resumed
# Verdict: { "verdict": "Block", "reason": "KillSwitch" }

# Resume normal operation
sentinel resume
```

### Recovery Procedures

#### After Suspected Compromise

1. **Kill switch**: `sentinel kill`
2. **Preserve logs**: `cp sentinel.log sentinel.log.incident`
3. **Rotate registry**: `sentinel registry export --backup && sentinel registry reset`
4. **Re-register tools**: `sentinel registry import --manifest approved_tools.json`
5. **Resume**: `sentinel resume`

#### After Config Error (Locked Out)

If you accidentally set config that blocks everything:

```bash
# Override config via environment
SENTINEL_REGISTRY_ALLOW_UNKNOWN=true sentinel start

# Or use rescue mode
sentinel start --rescue
# Rescue mode: fail_closed=false, allow_unknown_tools=true
```

#### Database Corruption

```bash
# Rebuild registry from backup
sentinel registry restore --backup ./backups/registry.db.bak

# Or rebuild from scratch
rm sentinel_registry.db
sentinel registry import --manifest approved_tools.json
```

---

## 8. Monitoring

### Logging

Sentinel logs all decisions to stdout and optionally to file:

```bash
# Start with file logging
sentinel start --config sentinel.toml --log-file ./sentinel.log

# Log levels: trace, debug, info, warn, error
RUST_LOG=sentinel=debug sentinel start
```

**Log Format**:

```
2026-01-11T05:00:00Z INFO sentinel: Tool call 'read_file' approved
2026-01-11T05:00:01Z WARN sentinel: Schema drift on 'write_file': Minor
2026-01-11T05:00:02Z ERROR sentinel: Council rejected 'delete_all': Dangerous pattern
```

### Metrics

Sentinel exposes Prometheus metrics at `/metrics`:

```bash
curl http://localhost:8080/metrics
```

**Key Metrics**:

| Metric | Description |
|--------|-------------|
| `sentinel_verdicts_total{verdict="allow\|block\|review"}` | Verdict counts |
| `sentinel_gas_used` | Gas consumption per request |
| `sentinel_council_votes{evaluator,decision}` | Evaluator voting patterns |
| `sentinel_waluigi_scores` | Waluigi score distribution |
| `sentinel_registry_drift_events` | Schema drift detections |

### Alerting

Configure alerts for critical events:

```yaml
# prometheus-alerts.yaml
groups:
  - name: sentinel
    rules:
      - alert: HighBlockRate
        expr: rate(sentinel_verdicts_total{verdict="block"}[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High block rate detected"

      - alert: WaluigiDetected
        expr: sentinel_waluigi_scores > 0.9
        for: 0s
        labels:
          severity: critical
        annotations:
          summary: "Waluigi effect detected - possible alignment issue"

      - alert: KillSwitchActive
        expr: sentinel_kill_switch_active == 1
        for: 0s
        labels:
          severity: critical
        annotations:
          summary: "Sentinel kill switch is active"
```

---

## 9. Troubleshooting

### Common Issues

#### "Unknown tool blocked" for legitimate tools

**Cause**: Tool not registered in registry.

**Fix**:
```bash
sentinel registry add --schema ./schemas/tool.json
# Or temporarily allow unknown tools:
sentinel config set registry.allow_unknown_tools true
```

#### "Gas exhausted" on complex tasks

**Cause**: Gas limit too low for workflow.

**Fix**:
```bash
sentinel config set monitor.gas_limit 50000
```

#### All requests being blocked

**Cause**: Possible config error or fail_closed with no registered tools.

**Fix**:
```bash
# Start in rescue mode
sentinel start --rescue

# Check config
sentinel config show

# Reset to defaults
sentinel config reset
```

#### "Cycle detected" false positives

**Cause**: Legitimate repetitive workflow flagged as loop.

**Fix**:
```bash
# Increase cycle detection window
sentinel config set monitor.cycle_window 20

# Or disable for specific tool patterns
sentinel policy add --tool "poll_*" --allow-cycles
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
RUST_LOG=sentinel=trace sentinel start --config sentinel.toml
```

Debug output shows:
- Every tool call and its parameters
- Registry lookup results
- Gas consumption per step
- Council vote breakdown
- Waluigi analysis scores

### Health Check

```bash
# Quick health check
sentinel health

# Expected output:
# ✓ Registry: OK (142 tools registered)
# ✓ Monitor: OK (gas_limit: 10000)
# ✓ Council: OK (3 evaluators active)
# ✓ Waluigi: OK (threshold: 0.70)
# Status: OPERATIONAL

# Detailed health
sentinel health --verbose
```

### Support

If issues persist:

1. Export diagnostics: `sentinel diag export --output ./diag.tar.gz`
2. Check logs for patterns: `grep -E "(ERROR|WARN)" sentinel.log`
3. Verify config: `sentinel config validate`
4. Test individual components: `sentinel test registry && sentinel test council`

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `sentinel start` | Start Sentinel proxy |
| `sentinel kill` | Emergency stop all traffic |
| `sentinel resume` | Resume after kill switch |
| `sentinel bypass issue` | Issue temporary bypass token |
| `sentinel registry add` | Register a tool schema |
| `sentinel registry list` | List registered tools |
| `sentinel review list` | Show pending reviews |
| `sentinel health` | Check system health |
| `sentinel config show` | Display current config |

---

*MIT License - Pixel Marmalade LLC*
