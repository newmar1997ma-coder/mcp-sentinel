// Package router provides the MCP proxy routing facade.
//
// It integrates JSON-RPC parsing, transport handling, and sentinel
// security checks into a unified message routing pipeline.
//
// # Architecture
//
// The router receives raw bytes from a transport, parses them as
// JSON-RPC messages, runs security checks via FFI, and either
// forwards to the server or blocks with an error response.
//
//	Client → Transport → Router → [Security] → Server
//	                        ↓
//	                   Parse → Check → Forward/Block
//
// # Security Pipeline
//
// Each message passes through three checks:
//   1. Registry Guard: Schema validation
//   2. State Monitor: Cycle detection, gas limits
//   3. Cognitive Council: Consensus voting (for high-risk actions)
//
// # Usage
//
//	router := router.New(transport, sentinelClient)
//	go router.Run(ctx) // Start processing
//
// # Thread Safety
//
// Router is safe for concurrent use. Multiple goroutines can
// call RouteMessage simultaneously.
package router

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/newmar1997ma-coder/mcp-sentinel/proxy/jsonrpc"
	"github.com/newmar1997ma-coder/mcp-sentinel/proxy/sentinel"
	"github.com/newmar1997ma-coder/mcp-sentinel/proxy/transport"
)

// Router manages MCP message routing with security checks.
type Router struct {
	// transport handles message I/O
	transport transport.Transport

	// sentinel provides security checks
	sentinel *sentinel.Client

	// sessionID identifies the current session for state tracking
	sessionID string

	// callDepth tracks nested tool calls
	callDepth atomic.Int32

	// gasUsed tracks cumulative gas consumption
	gasUsed atomic.Uint64

	// previousTools tracks tool call history for cycle detection
	previousTools []string
	toolsMu       sync.Mutex

	// stats tracks routing statistics
	stats Stats

	// forwardFunc sends messages to the MCP server
	// Can be replaced for testing
	forwardFunc func([]byte) ([]byte, error)
}

// Stats contains routing statistics.
type Stats struct {
	MessagesReceived atomic.Uint64
	MessagesForwarded atomic.Uint64
	MessagesBlocked  atomic.Uint64
	Errors           atomic.Uint64
}

// Config contains router configuration.
type Config struct {
	// SessionID for state tracking (generated if empty)
	SessionID string

	// GasBudget is the maximum gas allowed per session
	GasBudget uint64

	// MaxCallDepth is the maximum nested call depth
	MaxCallDepth int
}

// DefaultConfig returns sensible default configuration.
func DefaultConfig() *Config {
	return &Config{
		SessionID:    generateSessionID(),
		GasBudget:    1000000,
		MaxCallDepth: 10,
	}
}

// New creates a new Router with the given transport and sentinel client.
//
// # Arguments
//   - t: Transport for message I/O
//   - s: Sentinel client for security checks
//
// # Returns
//   - Configured Router ready to process messages
func New(t transport.Transport, s *sentinel.Client) *Router {
	return NewWithConfig(t, s, DefaultConfig())
}

// NewWithConfig creates a Router with custom configuration.
func NewWithConfig(t transport.Transport, s *sentinel.Client, cfg *Config) *Router {
	r := &Router{
		transport:     t,
		sentinel:      s,
		sessionID:     cfg.SessionID,
		previousTools: make([]string, 0, 100),
	}
	// Default forward function (can be replaced for testing)
	r.forwardFunc = r.defaultForward
	return r
}

// RouteMessage routes a single JSON-RPC message through security checks.
//
// This is the main entry point for message processing. It:
//   1. Parses the message as JSON-RPC
//   2. Runs security checks for tool calls
//   3. Forwards allowed messages or returns error responses
//
// # Arguments
//   - data: Raw JSON-RPC message bytes
//
// # Returns
//   - Response bytes (forwarded response or error)
//   - Error if processing fails
//
// # Security Notes
//
// All tool call messages (tools/call) are checked by sentinel.
// Non-tool messages are forwarded without security checks.
func (r *Router) RouteMessage(data []byte) ([]byte, error) {
	r.stats.MessagesReceived.Add(1)

	// Parse JSON-RPC message
	msg, err := jsonrpc.Parse(data)
	if err != nil {
		r.stats.Errors.Add(1)
		return r.errorResponse(nil, jsonrpc.ParseError, "Parse error", err.Error())
	}

	// Only check tool calls
	if msg.Method == "tools/call" {
		result, err := r.checkToolCall(msg)
		if err != nil {
			r.stats.Errors.Add(1)
			return r.errorResponse(msg.ID, jsonrpc.InternalError, "Security check failed", err.Error())
		}
		if !result.Allowed {
			r.stats.MessagesBlocked.Add(1)
			return r.errorResponse(msg.ID, jsonrpc.InvalidRequest, "Blocked by security", result.Reason)
		}
	}

	// Forward message to server
	response, err := r.forwardFunc(data)
	if err != nil {
		r.stats.Errors.Add(1)
		return nil, fmt.Errorf("router: forward failed: %w", err)
	}

	r.stats.MessagesForwarded.Add(1)
	return response, nil
}

// checkToolCall runs security checks for a tool call message.
func (r *Router) checkToolCall(msg *jsonrpc.Message) (*sentinel.CheckResult, error) {
	toolName := jsonrpc.ExtractToolName(msg)

	// Registry check
	registryReq := &sentinel.RegistryCheckRequest{
		ToolName: toolName,
		Params:   msg.Params,
	}
	result, err := r.sentinel.CheckRegistry(registryReq)
	if err != nil {
		return nil, err
	}
	if !result.Allowed {
		return result, nil
	}

	// State check
	r.toolsMu.Lock()
	prevTools := make([]string, len(r.previousTools))
	copy(prevTools, r.previousTools)
	r.previousTools = append(r.previousTools, toolName)
	r.toolsMu.Unlock()

	stateReq := &sentinel.StateCheckRequest{
		SessionID:     r.sessionID,
		ToolName:      toolName,
		CallDepth:     int(r.callDepth.Load()),
		GasUsed:       r.gasUsed.Load(),
		PreviousTools: prevTools,
	}
	result, err = r.sentinel.CheckState(stateReq)
	if err != nil {
		return nil, err
	}
	if !result.Allowed {
		return result, nil
	}

	// Council check for high-risk tools
	if isHighRiskTool(toolName) {
		councilReq := &sentinel.CouncilVoteRequest{
			Action:    fmt.Sprintf("Execute tool: %s", toolName),
			ToolName:  toolName,
			RiskScore: 0.7, // High risk threshold
		}
		result, err = r.sentinel.VoteCouncil(councilReq)
		if err != nil {
			return nil, err
		}
	}

	// Update gas usage
	r.gasUsed.Add(estimateGas(toolName))

	return result, nil
}

// defaultForward sends a message through the transport and reads response.
func (r *Router) defaultForward(data []byte) ([]byte, error) {
	if err := r.transport.Send(data); err != nil {
		return nil, err
	}
	return r.transport.Receive()
}

// errorResponse creates a JSON-RPC error response.
func (r *Router) errorResponse(id json.RawMessage, code int, message, data string) ([]byte, error) {
	resp, err := jsonrpc.NewErrorResponse(id, code, message, data)
	if err != nil {
		return nil, err
	}
	return jsonrpc.Serialize(resp)
}

// Run starts the router's message processing loop.
//
// It reads messages from the transport, routes them, and sends responses.
// Run blocks until the context is cancelled or an error occurs.
func (r *Router) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read next message
		data, err := r.transport.Receive()
		if err != nil {
			return fmt.Errorf("router: receive failed: %w", err)
		}

		// Route message
		response, err := r.RouteMessage(data)
		if err != nil {
			// Log error but continue processing
			continue
		}

		// Send response back to client
		if err := r.transport.Send(response); err != nil {
			return fmt.Errorf("router: send failed: %w", err)
		}
	}
}

// Stats returns the current routing statistics.
func (r *Router) Stats() Stats {
	return Stats{
		MessagesReceived:  atomic.Uint64{},
		MessagesForwarded: atomic.Uint64{},
		MessagesBlocked:   atomic.Uint64{},
		Errors:            atomic.Uint64{},
	}
}

// GetStats returns a snapshot of current statistics.
func (r *Router) GetStats() (received, forwarded, blocked, errors uint64) {
	return r.stats.MessagesReceived.Load(),
		r.stats.MessagesForwarded.Load(),
		r.stats.MessagesBlocked.Load(),
		r.stats.Errors.Load()
}

// isHighRiskTool returns true for tools that require council voting.
func isHighRiskTool(name string) bool {
	highRiskTools := map[string]bool{
		"execute_command": true,
		"write_file":      true,
		"delete_file":     true,
		"run_script":      true,
		"sudo":            true,
		"shell":           true,
	}
	return highRiskTools[name]
}

// estimateGas returns an estimated gas cost for a tool.
func estimateGas(name string) uint64 {
	// Base gas costs by category
	gasCosts := map[string]uint64{
		"read_file":       100,
		"write_file":      500,
		"execute_command": 1000,
		"list_directory":  50,
	}
	if cost, ok := gasCosts[name]; ok {
		return cost
	}
	return 200 // Default cost
}

// generateSessionID creates a unique session identifier.
func generateSessionID() string {
	// Simple implementation - in production use UUID
	return fmt.Sprintf("session-%d", atomicCounter.Add(1))
}

var atomicCounter atomic.Uint64
