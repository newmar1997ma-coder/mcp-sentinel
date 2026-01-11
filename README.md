<p align="center">
  <img src="https://img.shields.io/badge/tests-435%20passing-brightgreen?style=for-the-badge" alt="Tests">
  <img src="https://img.shields.io/badge/rust-16%2C000%2B%20lines-orange?style=for-the-badge&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/go-proxy-00ADD8?style=for-the-badge&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/react-dashboard-61DAFB?style=for-the-badge&logo=react" alt="React">
</p>

# MCP Sentinel

**Active Defense Framework for Model Context Protocol**

> When AI agents can execute arbitrary tools, who watches the watchers?

MCP Sentinel is a security gateway that intercepts, analyzes, and controls every tool call between AI agents and MCP servers. It provides real-time threat detection, policy enforcement, and human-in-the-loop escalation before dangerous operations execute.

---

## The Problem

The Model Context Protocol (MCP) gives AI agents powerful capabilities: file access, code execution, API calls, database queries. But this power creates risk:

| Threat | Description | Impact |
|--------|-------------|--------|
| **Rug Pulls** | MCP server updates tool schemas maliciously after trust is established | Agent executes unintended operations |
| **Prompt Injection** | Malicious input hijacks agent behavior via tool responses | Data exfiltration, unauthorized actions |
| **Infinite Loops** | Agent trapped in recursive tool calls, burning resources | DoS, cost explosion |
| **Alignment Drift** | Subtle manipulation causes agent to deviate from user intent | Silent compromise |

**MCP Sentinel eliminates these threats.**

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              MCP SENTINEL                                        │
│                                                                                  │
│   ┌──────────┐    ┌─────────────────────────────────────────────────────────┐   │
│   │ AI Agent │    │                  SECURITY PIPELINE                      │   │
│   │ (Claude) │───▶│                                                         │   │
│   └──────────┘    │  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │   │
│                   │  │   Registry   │  │    State     │  │   Cognitive   │  │   │
│                   │  │    Guard     │─▶│   Monitor    │─▶│    Council    │  │   │
│                   │  └──────────────┘  └──────────────┘  └───────────────┘  │   │
│                   │        │                 │                  │           │   │
│                   │        ▼                 ▼                  ▼           │   │
│                   │   Schema Drift      Cycle Detection    Consensus Vote   │   │
│                   │   Hash Verify       Gas Budgeting      Waluigi Defense  │   │
│                   │   Rug Pull Block    Context Overflow   Alignment Check  │   │
│                   └─────────────────────────────────────────────────────────┘   │
│                                              │                                   │
│                                              ▼                                   │
│                                    ┌─────────────────┐                          │
│                                    │     VERDICT     │                          │
│                                    │  Allow | Block  │                          │
│                                    │     | Review    │                          │
│                                    └─────────────────┘                          │
│                                              │                                   │
└──────────────────────────────────────────────┼───────────────────────────────────┘
                                               │
                                               ▼
                                     ┌─────────────────┐
                                     │   MCP Server    │
                                     │    (Tools)      │
                                     └─────────────────┘
```

---

## Components

### Security Crates (Rust)

| Crate | Purpose | Threat Coverage |
|-------|---------|-----------------|
| **sentinel-core** | Unified facade, verdict types, configuration | Central orchestration |
| **sentinel-registry** | Merkle tree of tool schemas, drift detection | Rug pulls, schema tampering |
| **sentinel-monitor** | Gas budgeting, cycle detection, context tracking | DoS, infinite loops, resource exhaustion |
| **sentinel-council** | 3-evaluator consensus voting, Waluigi detector | Alignment drift, jailbreaks |
| **sentinel-firewall** | Pattern matching, entropy analysis, canary tokens | Prompt injection, data exfiltration |

### Proxy Router (Go)

| Package | Purpose |
|---------|---------|
| **router** | Request routing to MCP servers |
| **transport** | Protocol handling (stdio, HTTP, WebSocket) |
| **middleware** | Request/response interception chain |

### Operations Dashboard (React)

| Feature | Description |
|---------|-------------|
| **Status Panel** | Real-time component health |
| **Verdict Feed** | Live Allow/Block/Review stream |
| **Threat Log** | Incident details with severity filtering |
| **Config Editor** | View/modify sentinel.toml with TOML preview |
| **Metrics** | Request counts, latency, verdict distribution |

---

## Quick Start

### Prerequisites

- Rust 1.70+
- Go 1.21+
- Node.js 18+ (for dashboard)

### Build

```bash
# Clone repository
git clone https://github.com/pixel-marmalade/mcp-sentinel.git
cd mcp-sentinel

# Build Rust crates
cargo build --release

# Run tests (435 tests)
cargo test --all

# Build Go proxy
cd proxy && go build -o mcp-sentinel-proxy && cd ..

# Start dashboard
cd dashboard && npm install && npm run dev
```

### Configure

```bash
# Copy example config
cp config/sentinel.example.toml config/sentinel.toml

# Edit for your environment
vim config/sentinel.toml
```

### Run

```bash
# Start Sentinel
./target/release/sentinel start --config config/sentinel.toml

# Verify health
curl http://localhost:8080/health
# {"status":"healthy","components":{"registry":"ok","monitor":"ok","council":"ok"}}
```

---

## Verdict Types

Every tool call receives one of three verdicts:

| Verdict | Meaning | Action |
|---------|---------|--------|
| **Allow** | Passed all security checks | Forward to MCP server |
| **Block** | Failed security checks | Reject with reason |
| **Review** | Requires human approval | Queue for operator decision |

### Block Reasons

- `SchemaDrift` - Tool schema changed from registered version
- `HashMismatch` - Merkle hash mismatch (rug pull detected)
- `CycleDetected` - Execution loop detected
- `GasExhausted` - Resource budget exceeded
- `CouncilRejected` - Evaluators voted against
- `WaluigiEffect` - Alignment inversion detected

---

## Dashboard

<p align="center">
  <em>Operations dashboard for real-time monitoring</em>
</p>

```bash
cd dashboard && npm run dev
# Open http://localhost:5173
```

Features dark theme, live verdict feed, threat log with severity filtering, and configuration editor with TOML preview.

---

## Documentation

| Document | Description |
|----------|-------------|
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Production deployment guide, emergency procedures |
| [config/sentinel.example.toml](./config/sentinel.example.toml) | Configuration reference |

---

## Tech Stack

| Layer | Technology | Lines of Code |
|-------|------------|---------------|
| **Security Core** | Rust | 16,000+ |
| **Proxy Router** | Go | 2,000+ |
| **Dashboard** | React + Vite + Tailwind | 4,000+ |
| **Tests** | Rust (cargo test) | 435 tests |

---

## Project Structure

```
mcp_sentinel/
├── crates/
│   ├── sentinel-core/       # Unified facade, verdicts, config
│   ├── sentinel-registry/   # Merkle tree, schema verification
│   ├── sentinel-monitor/    # Gas, cycles, context tracking
│   ├── sentinel-council/    # Consensus voting, Waluigi defense
│   ├── sentinel-firewall/   # Patterns, entropy, canaries
│   └── sentinel-cli/        # Command-line interface
├── proxy/                   # Go proxy router
├── dashboard/               # React operations UI
├── config/                  # Configuration files
├── DEPLOYMENT.md            # Production guide
└── README.md                # You are here
```

---

## Security Model

MCP Sentinel operates on a **fail-closed** principle:

1. **Default Deny** - Unknown tools blocked unless explicitly registered
2. **Defense in Depth** - Multiple independent security layers
3. **Human in the Loop** - Uncertain decisions escalate to operators
4. **Audit Trail** - Every verdict logged with full context

---

## License

MIT License - [Pixel Marmalade LLC](https://pixel-marmalade.io)

---

<p align="center">
  <strong>MCP Sentinel</strong> - Active Defense for AI Agents
  <br>
  <em>Trust, but verify. Then verify again.</em>
</p>
