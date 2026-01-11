// Package proxy implements the MCP Sentinel proxy router.
//
// It intercepts MCP JSON-RPC traffic between clients and servers,
// routing messages through Rust security components via FFI for
// security analysis before forwarding or blocking.
//
// # Threat Model
//
// The proxy defends against:
//
//   - Malicious MCP servers sending poisoned tool responses
//   - Prompt injection via tool results or resource content
//   - Schema violations and unexpected message formats
//   - State manipulation through cyclic dependencies
//   - Transport-level attacks (MITM on stdio/SSE)
//
// # Architecture
//
// The proxy sits between MCP clients and servers:
//
//	Client → Proxy → [FFI Security Check] → Server
//	                       ↓
//	              ┌────────┴────────┐
//	              ↓        ↓        ↓
//	           Registry  State   Council
//	            Guard   Monitor   (vote)
//
// All messages pass through three Rust security components:
//
//   - Registry Guard: Schema validation and Merkle verification
//   - State Monitor: Cycle detection and gas budgeting
//   - Cognitive Council: Consensus voting on ambiguous cases
//
// # Transports
//
// Two transport modes are supported:
//
//   - Stdio: Standard input/output for subprocess MCP servers
//   - SSE: HTTP Server-Sent Events for remote MCP servers
//
// # FFI Bridge
//
// The proxy calls Rust sentinel crates via cgo FFI. Stubs are provided
// for development; actual linking occurs during integration build.
//
// # Usage
//
//	proxy := NewProxy(StdioTransport{})
//	response, err := proxy.RouteMessage(jsonRpcBytes)
//	if err != nil {
//	    // Message blocked by security check
//	}
package proxy
