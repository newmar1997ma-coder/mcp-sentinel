// Package jsonrpc provides JSON-RPC 2.0 message parsing for MCP.
//
// It handles parsing and serialization of JSON-RPC messages used
// in the Model Context Protocol (MCP), including requests, responses,
// notifications, and error handling.
//
// # Message Types
//
// The package handles three message types per JSON-RPC 2.0:
//
//   - Request: Has method, params, and id (expects response)
//   - Notification: Has method and params but no id (fire-and-forget)
//   - Response: Has result or error, and id matching a request
//
// # MCP-Specific Methods
//
// Common MCP methods intercepted by the proxy:
//
//   - tools/list: List available tools
//   - tools/call: Execute a tool
//   - resources/list: List available resources
//   - resources/read: Read resource content
//   - prompts/list: List available prompts
//   - prompts/get: Get a prompt template
//
// # Security Notes
//
// All parsed messages are validated for:
//   - Required fields (jsonrpc version must be "2.0")
//   - Valid ID types (string, number, or null)
//   - Method string format
//
// Invalid messages return parsing errors rather than partial results.
package jsonrpc

import (
	"encoding/json"
	"errors"
	"fmt"
)

// JSON-RPC 2.0 version constant.
const Version = "2.0"

// Common errors returned by the parser.
var (
	ErrInvalidJSON    = errors.New("jsonrpc: invalid JSON")
	ErrInvalidVersion = errors.New("jsonrpc: version must be 2.0")
	ErrMissingMethod  = errors.New("jsonrpc: missing method field")
	ErrInvalidID      = errors.New("jsonrpc: invalid id type")
)

// JSON-RPC 2.0 error codes.
const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

// Message represents a JSON-RPC 2.0 message.
//
// It can be a request (has method and id), notification (has method, no id),
// or response (has result or error, and id). Use the Type() method to
// determine which kind of message this is.
type Message struct {
	// JSONRPC version, must be "2.0"
	JSONRPC string `json:"jsonrpc"`

	// Method name for requests and notifications
	Method string `json:"method,omitempty"`

	// Params for requests and notifications (object or array)
	Params json.RawMessage `json:"params,omitempty"`

	// ID for requests and responses (string, number, or null)
	// Notifications have no ID field
	ID json.RawMessage `json:"id,omitempty"`

	// Result for successful responses
	Result json.RawMessage `json:"result,omitempty"`

	// Error for failed responses
	Error *Error `json:"error,omitempty"`
}

// Error represents a JSON-RPC 2.0 error object.
type Error struct {
	// Code is the error code (negative integers for protocol errors)
	Code int `json:"code"`

	// Message is a short description of the error
	Message string `json:"message"`

	// Data contains additional error information (optional)
	Data json.RawMessage `json:"data,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// MessageType indicates the type of JSON-RPC message.
type MessageType int

const (
	// TypeUnknown indicates an unparseable or invalid message
	TypeUnknown MessageType = iota
	// TypeRequest indicates a request expecting a response
	TypeRequest
	// TypeNotification indicates a notification (no response expected)
	TypeNotification
	// TypeResponse indicates a response to a previous request
	TypeResponse
)

// String returns the string representation of the message type.
func (t MessageType) String() string {
	switch t {
	case TypeRequest:
		return "request"
	case TypeNotification:
		return "notification"
	case TypeResponse:
		return "response"
	default:
		return "unknown"
	}
}

// Type returns the message type based on which fields are present.
//
// - Request: has method and id
// - Notification: has method but no id
// - Response: has result or error (and id)
func (m *Message) Type() MessageType {
	hasMethod := m.Method != ""
	hasID := len(m.ID) > 0 && string(m.ID) != "null"
	hasResult := len(m.Result) > 0
	hasError := m.Error != nil

	if hasResult || hasError {
		return TypeResponse
	}
	if hasMethod && hasID {
		return TypeRequest
	}
	if hasMethod && !hasID {
		return TypeNotification
	}
	return TypeUnknown
}

// Parse parses a raw JSON-RPC message from bytes.
//
// It validates that the message is valid JSON and conforms to JSON-RPC 2.0
// requirements. Returns an error if the message is malformed.
//
// # Arguments
//   - data: Raw JSON bytes to parse
//
// # Returns
//   - Parsed Message struct
//   - Error if parsing or validation fails
//
// # Example
//
//	msg, err := jsonrpc.Parse([]byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(msg.Method) // "tools/list"
func Parse(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	// Validate version
	if msg.JSONRPC != Version {
		return nil, ErrInvalidVersion
	}

	// Requests and notifications must have a method
	if msg.Type() == TypeUnknown {
		if msg.Method == "" && msg.Result == nil && msg.Error == nil {
			return nil, ErrMissingMethod
		}
	}

	return &msg, nil
}

// Serialize converts a Message to JSON bytes.
//
// # Arguments
//   - msg: Message to serialize
//
// # Returns
//   - JSON bytes
//   - Error if serialization fails
//
// # Example
//
//	msg := &jsonrpc.Message{
//	    JSONRPC: jsonrpc.Version,
//	    Method:  "tools/list",
//	    ID:      json.RawMessage(`1`),
//	}
//	data, err := jsonrpc.Serialize(msg)
func Serialize(msg *Message) ([]byte, error) {
	return json.Marshal(msg)
}

// NewRequest creates a new JSON-RPC request message.
//
// # Arguments
//   - method: The method name to call
//   - params: Parameters for the method (will be JSON-encoded)
//   - id: Request ID (string or int)
//
// # Returns
//   - New Message configured as a request
//   - Error if params cannot be encoded
func NewRequest(method string, params interface{}, id interface{}) (*Message, error) {
	msg := &Message{
		JSONRPC: Version,
		Method:  method,
	}

	// Encode params if provided
	if params != nil {
		p, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("failed to encode params: %w", err)
		}
		msg.Params = p
	}

	// Encode ID
	idBytes, err := json.Marshal(id)
	if err != nil {
		return nil, fmt.Errorf("failed to encode id: %w", err)
	}
	msg.ID = idBytes

	return msg, nil
}

// NewNotification creates a new JSON-RPC notification message.
//
// Notifications are requests that don't expect a response.
//
// # Arguments
//   - method: The method name
//   - params: Parameters for the method
//
// # Returns
//   - New Message configured as a notification
//   - Error if params cannot be encoded
func NewNotification(method string, params interface{}) (*Message, error) {
	msg := &Message{
		JSONRPC: Version,
		Method:  method,
	}

	if params != nil {
		p, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("failed to encode params: %w", err)
		}
		msg.Params = p
	}

	return msg, nil
}

// NewResponse creates a new JSON-RPC response message.
//
// # Arguments
//   - id: Request ID this is responding to
//   - result: Result data (will be JSON-encoded)
//
// # Returns
//   - New Message configured as a success response
//   - Error if result cannot be encoded
func NewResponse(id json.RawMessage, result interface{}) (*Message, error) {
	msg := &Message{
		JSONRPC: Version,
		ID:      id,
	}

	r, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to encode result: %w", err)
	}
	msg.Result = r

	return msg, nil
}

// NewErrorResponse creates a new JSON-RPC error response.
//
// # Arguments
//   - id: Request ID this is responding to (nil for parse errors)
//   - code: Error code (use constants like ParseError, InvalidRequest)
//   - message: Human-readable error message
//   - data: Optional additional error data
//
// # Returns
//   - New Message configured as an error response
func NewErrorResponse(id json.RawMessage, code int, message string, data interface{}) (*Message, error) {
	msg := &Message{
		JSONRPC: Version,
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	}

	if data != nil {
		d, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to encode error data: %w", err)
		}
		msg.Error.Data = d
	}

	return msg, nil
}

// IsMCPMethod checks if the method is a known MCP method.
//
// This helps identify MCP-specific methods for security analysis.
func IsMCPMethod(method string) bool {
	mcpMethods := map[string]bool{
		"initialize":         true,
		"initialized":        true,
		"ping":               true,
		"tools/list":         true,
		"tools/call":         true,
		"resources/list":     true,
		"resources/read":     true,
		"resources/subscribe": true,
		"prompts/list":       true,
		"prompts/get":        true,
		"logging/setLevel":   true,
		"completion/complete": true,
	}
	return mcpMethods[method]
}

// ExtractToolName extracts the tool name from a tools/call params.
//
// Returns empty string if not a tools/call message or if name not found.
func ExtractToolName(msg *Message) string {
	if msg.Method != "tools/call" || len(msg.Params) == 0 {
		return ""
	}

	var params struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return ""
	}
	return params.Name
}
