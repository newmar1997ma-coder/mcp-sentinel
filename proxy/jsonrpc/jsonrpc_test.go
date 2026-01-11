package jsonrpc

import (
	"encoding/json"
	"testing"
)

func TestParse_ValidRequest(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if msg.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc '2.0', got %q", msg.JSONRPC)
	}
	if msg.Method != "tools/list" {
		t.Errorf("expected method 'tools/list', got %q", msg.Method)
	}
	if msg.Type() != TypeRequest {
		t.Errorf("expected TypeRequest, got %v", msg.Type())
	}
}

func TestParse_ValidNotification(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","method":"initialized"}`)
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if msg.Type() != TypeNotification {
		t.Errorf("expected TypeNotification, got %v", msg.Type())
	}
}

func TestParse_ValidResponse(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`)
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if msg.Type() != TypeResponse {
		t.Errorf("expected TypeResponse, got %v", msg.Type())
	}
}

func TestParse_ErrorResponse(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":1}`)
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if msg.Type() != TypeResponse {
		t.Errorf("expected TypeResponse, got %v", msg.Type())
	}
	if msg.Error == nil {
		t.Error("expected error to be set")
	}
	if msg.Error.Code != InvalidRequest {
		t.Errorf("expected code %d, got %d", InvalidRequest, msg.Error.Code)
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	data := []byte(`{invalid}`)
	_, err := Parse(data)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParse_WrongVersion(t *testing.T) {
	data := []byte(`{"jsonrpc":"1.0","method":"test","id":1}`)
	_, err := Parse(data)
	if err == nil {
		t.Error("expected error for wrong version")
	}
	if err != ErrInvalidVersion {
		t.Errorf("expected ErrInvalidVersion, got %v", err)
	}
}

func TestSerialize(t *testing.T) {
	msg := &Message{
		JSONRPC: Version,
		Method:  "test",
		ID:      json.RawMessage(`1`),
	}

	data, err := Serialize(msg)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Parse it back
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse of serialized data failed: %v", err)
	}

	if parsed.Method != "test" {
		t.Errorf("expected method 'test', got %q", parsed.Method)
	}
}

func TestNewRequest(t *testing.T) {
	params := map[string]string{"key": "value"}
	msg, err := NewRequest("test/method", params, 42)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	if msg.JSONRPC != Version {
		t.Errorf("expected version %q, got %q", Version, msg.JSONRPC)
	}
	if msg.Method != "test/method" {
		t.Errorf("expected method 'test/method', got %q", msg.Method)
	}
	if msg.Type() != TypeRequest {
		t.Errorf("expected TypeRequest, got %v", msg.Type())
	}
}

func TestNewNotification(t *testing.T) {
	msg, err := NewNotification("notify", nil)
	if err != nil {
		t.Fatalf("NewNotification failed: %v", err)
	}

	if msg.Type() != TypeNotification {
		t.Errorf("expected TypeNotification, got %v", msg.Type())
	}
	if len(msg.ID) != 0 {
		t.Error("notification should not have ID")
	}
}

func TestNewResponse(t *testing.T) {
	result := map[string]int{"count": 5}
	msg, err := NewResponse(json.RawMessage(`1`), result)
	if err != nil {
		t.Fatalf("NewResponse failed: %v", err)
	}

	if msg.Type() != TypeResponse {
		t.Errorf("expected TypeResponse, got %v", msg.Type())
	}
	if len(msg.Result) == 0 {
		t.Error("response should have result")
	}
}

func TestNewErrorResponse(t *testing.T) {
	msg, err := NewErrorResponse(json.RawMessage(`1`), InvalidRequest, "Bad request", nil)
	if err != nil {
		t.Fatalf("NewErrorResponse failed: %v", err)
	}

	if msg.Type() != TypeResponse {
		t.Errorf("expected TypeResponse, got %v", msg.Type())
	}
	if msg.Error == nil {
		t.Error("expected error to be set")
	}
	if msg.Error.Code != InvalidRequest {
		t.Errorf("expected code %d, got %d", InvalidRequest, msg.Error.Code)
	}
}

func TestIsMCPMethod(t *testing.T) {
	tests := []struct {
		method   string
		expected bool
	}{
		{"initialize", true},
		{"tools/list", true},
		{"tools/call", true},
		{"resources/read", true},
		{"prompts/get", true},
		{"unknown/method", false},
		{"", false},
	}

	for _, tt := range tests {
		result := IsMCPMethod(tt.method)
		if result != tt.expected {
			t.Errorf("IsMCPMethod(%q) = %v, expected %v", tt.method, result, tt.expected)
		}
	}
}

func TestExtractToolName(t *testing.T) {
	// Test with valid tools/call message
	params := json.RawMessage(`{"name":"read_file","arguments":{}}`)
	msg := &Message{
		JSONRPC: Version,
		Method:  "tools/call",
		Params:  params,
	}

	name := ExtractToolName(msg)
	if name != "read_file" {
		t.Errorf("expected 'read_file', got %q", name)
	}

	// Test with non-tools/call message
	msg.Method = "tools/list"
	name = ExtractToolName(msg)
	if name != "" {
		t.Errorf("expected empty string for non-tools/call, got %q", name)
	}

	// Test with invalid params
	msg.Method = "tools/call"
	msg.Params = json.RawMessage(`invalid`)
	name = ExtractToolName(msg)
	if name != "" {
		t.Errorf("expected empty string for invalid params, got %q", name)
	}
}

func TestMessageType_String(t *testing.T) {
	tests := []struct {
		t        MessageType
		expected string
	}{
		{TypeRequest, "request"},
		{TypeNotification, "notification"},
		{TypeResponse, "response"},
		{TypeUnknown, "unknown"},
	}

	for _, tt := range tests {
		result := tt.t.String()
		if result != tt.expected {
			t.Errorf("MessageType(%d).String() = %q, expected %q", tt.t, result, tt.expected)
		}
	}
}

func TestError_Error(t *testing.T) {
	e := &Error{
		Code:    ParseError,
		Message: "Parse error",
	}

	expected := "jsonrpc error -32700: Parse error"
	if e.Error() != expected {
		t.Errorf("Error() = %q, expected %q", e.Error(), expected)
	}
}
