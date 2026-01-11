// Package sentinel provides FFI bridge to Rust sentinel crates.
//
// This package bridges Go to the Rust security components via cgo.
// In the stub implementation, all security checks pass. During
// integration build, the actual Rust libraries will be linked.
//
// # Components
//
// Three Rust crates are accessed via FFI:
//
//   - Registry Guard: Schema validation and Merkle verification
//   - State Monitor: Cycle detection and gas budgeting
//   - Cognitive Council: Consensus voting on ambiguous actions
//
// # FFI Contract
//
// Each function accepts JSON-encoded data and returns a boolean result.
// The Rust side handles deserialization and processing.
//
// # Build Modes
//
// Development (default): Uses stub implementations that always allow
// Integration: Link against libsentinel.a with CGO_ENABLED=1
//
// To enable Rust FFI linking, build with:
//
//	CGO_ENABLED=1 go build -tags ffi ./...
//
// # Security Notes
//
//   - All security decisions are made by Rust code
//   - Go layer is pass-through for transport handling
//   - FFI boundary is the trust boundary
package sentinel

import (
	"encoding/json"
	"errors"
)

// Common errors returned by sentinel checks.
var (
	ErrRegistryInvalid  = errors.New("sentinel: registry validation failed")
	ErrStateCycle       = errors.New("sentinel: state cycle detected")
	ErrStateGasExceeded = errors.New("sentinel: gas budget exceeded")
	ErrCouncilRejected  = errors.New("sentinel: council rejected action")
	ErrFFICall          = errors.New("sentinel: FFI call failed")
)

// RegistryCheckRequest contains data for registry validation.
type RegistryCheckRequest struct {
	// SchemaID identifies the tool schema to validate against
	SchemaID string `json:"schema_id"`

	// ToolName is the tool being invoked
	ToolName string `json:"tool_name"`

	// Params are the tool parameters to validate
	Params json.RawMessage `json:"params"`

	// ServerID identifies the MCP server
	ServerID string `json:"server_id,omitempty"`
}

// StateCheckRequest contains data for state validation.
type StateCheckRequest struct {
	// SessionID identifies the current session
	SessionID string `json:"session_id"`

	// ToolName is the tool being invoked
	ToolName string `json:"tool_name"`

	// CallDepth is the current call stack depth
	CallDepth int `json:"call_depth"`

	// GasUsed is the current gas consumption
	GasUsed uint64 `json:"gas_used"`

	// PreviousTools lists tools called in this session
	PreviousTools []string `json:"previous_tools,omitempty"`
}

// CouncilVoteRequest contains data for council voting.
type CouncilVoteRequest struct {
	// Action describes what the agent wants to do
	Action string `json:"action"`

	// ToolName is the tool being invoked
	ToolName string `json:"tool_name"`

	// Risk level from 0.0 to 1.0
	RiskScore float64 `json:"risk_score"`

	// Context provides additional information for voting
	Context map[string]interface{} `json:"context,omitempty"`
}

// CheckResult contains the result of a security check.
type CheckResult struct {
	// Allowed indicates if the action should proceed
	Allowed bool

	// Reason explains why the action was allowed or blocked
	Reason string

	// Details contains additional diagnostic information
	Details map[string]interface{}
}

// Client provides the FFI bridge to Rust sentinel crates.
//
// The client is safe for concurrent use. All methods that call
// into Rust are protected by a mutex.
//
// In stub mode (default build), all checks pass immediately.
// With FFI enabled (build tag: ffi), calls route to Rust.
type Client struct {
	// impl is the actual implementation (stub or FFI)
	impl clientImpl
}

// clientImpl defines the interface for sentinel implementations.
type clientImpl interface {
	checkRegistry(req *RegistryCheckRequest) (*CheckResult, error)
	checkState(req *StateCheckRequest) (*CheckResult, error)
	voteCouncil(req *CouncilVoteRequest) (*CheckResult, error)
}

// NewClient creates a new sentinel client.
//
// In stub mode (default), all checks pass immediately.
// With FFI enabled, calls route to Rust implementations.
func NewClient() *Client {
	return &Client{
		impl: newClientImpl(),
	}
}

// CheckRegistry validates tool parameters against the schema registry.
//
// This calls the Registry Guard Rust crate to verify:
//   - Tool exists in registry
//   - Parameters match schema
//   - Merkle proof validates integrity
//
// # Arguments
//   - req: Registry check request with tool and params
//
// # Returns
//   - CheckResult indicating pass/fail and reason
//   - Error if FFI call fails
func (c *Client) CheckRegistry(req *RegistryCheckRequest) (*CheckResult, error) {
	return c.impl.checkRegistry(req)
}

// CheckState validates state transitions to detect cycles and gas limits.
//
// This calls the State Monitor Rust crate to verify:
//   - No cyclic tool invocations
//   - Gas budget not exceeded
//   - Context size within limits
//
// # Arguments
//   - req: State check request with session and tool info
//
// # Returns
//   - CheckResult indicating pass/fail and reason
//   - Error if FFI call fails
func (c *Client) CheckState(req *StateCheckRequest) (*CheckResult, error) {
	return c.impl.checkState(req)
}

// VoteCouncil submits an action to the Cognitive Council for voting.
//
// This calls the Cognitive Council Rust crate for:
//   - Consensus voting on ambiguous actions
//   - Waluigi defense against adversarial prompts
//   - Multi-perspective risk assessment
//
// # Arguments
//   - req: Council vote request with action and risk info
//
// # Returns
//   - CheckResult indicating approval/rejection and reason
//   - Error if FFI call fails
func (c *Client) VoteCouncil(req *CouncilVoteRequest) (*CheckResult, error) {
	return c.impl.voteCouncil(req)
}

// CheckCouncil is an alias for VoteCouncil for API consistency.
func (c *Client) CheckCouncil(req *CouncilVoteRequest) (*CheckResult, error) {
	return c.VoteCouncil(req)
}

// CheckAll runs all security checks in sequence.
//
// This is a convenience method that runs registry, state, and council
// checks in order. If any check fails, it returns immediately.
//
// # Arguments
//   - registry: Registry check request
//   - state: State check request
//   - council: Council vote request (optional, nil to skip)
//
// # Returns
//   - Combined CheckResult
//   - Error if any FFI call fails
func (c *Client) CheckAll(
	registry *RegistryCheckRequest,
	state *StateCheckRequest,
	council *CouncilVoteRequest,
) (*CheckResult, error) {
	// Check registry first
	result, err := c.CheckRegistry(registry)
	if err != nil {
		return nil, err
	}
	if !result.Allowed {
		return result, nil
	}

	// Check state
	result, err = c.CheckState(state)
	if err != nil {
		return nil, err
	}
	if !result.Allowed {
		return result, nil
	}

	// Check council if requested
	if council != nil {
		result, err = c.CheckCouncil(council)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}
