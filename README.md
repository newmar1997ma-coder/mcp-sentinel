# MCP Sentinel

**Active Defense Framework for Model Context Protocol**

MCP Sentinel is a security gateway that sits between AI agents and MCP servers, providing policy enforcement, anomaly detection, and human-in-the-loop escalation.

## Architecture

```
┌─────────────┐     ┌─────────────────────────────────────────┐     ┌─────────────┐
│  AI Agent   │────▶│            MCP Sentinel                 │────▶│ MCP Server  │
│  (Claude)   │◀────│  [Proxy] ─▶ [Firewall] ─▶ [Monitor]    │◀────│   (Tools)   │
└─────────────┘     └─────────────────────────────────────────┘     └─────────────┘
```

## Components

### Rust Crates (`crates/`)

- **sentinel-core** - Foundation types, policies, and error handling
- **sentinel-firewall** - Request filtering and blocking rules
- **sentinel-registry** - Server and tool capability registration
- **sentinel-monitor** - Logging, metrics, and anomaly detection
- **sentinel-council** - Multi-agent consensus for high-risk decisions
- **sentinel-cli** - Command-line interface

### Go Proxy (`proxy/`)

- **router** - Request routing to MCP servers
- **transport** - Protocol handling (stdio, HTTP, WebSocket)
- **middleware** - Request/response interception chain
- **sentinel** - Integration with Rust sentinel core

## Quick Start

```bash
# Build Rust components
cargo build --release

# Build Go proxy
cd proxy && go build -o mcp-sentinel-proxy

# Run with config
./target/release/sentinel start --config config/sentinel.toml
```

## Configuration

See `config/sentinel.example.toml` for configuration options.

## License

MIT - Pixel Marmalade LLC
