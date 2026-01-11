package router

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/newmar1997ma-coder/mcp-sentinel/proxy/jsonrpc"
	"github.com/newmar1997ma-coder/mcp-sentinel/proxy/sentinel"
)

// mockTransport implements transport.Transport for testing.
type mockTransport struct {
	sendFunc    func([]byte) error
	receiveFunc func() ([]byte, error)
	closeFunc   func() error
}

func (m *mockTransport) Send(data []byte) error {
	if m.sendFunc != nil {
		return m.sendFunc(data)
	}
	return nil
}

func (m *mockTransport) Receive() ([]byte, error) {
	if m.receiveFunc != nil {
		return m.receiveFunc()
	}
	return nil, errors.New("no receive function")
}

func (m *mockTransport) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func TestRouteMessage_ValidRequest(t *testing.T) {
	// Create mock transport
	mt := &mockTransport{}

	// Create router with stub sentinel
	s := sentinel.NewClient()
	r := New(mt, s)

	// Mock the forward function to return a success response
	r.forwardFunc = func(data []byte) ([]byte, error) {
		resp, _ := jsonrpc.NewResponse(json.RawMessage(`1`), map[string]string{"status": "ok"})
		return jsonrpc.Serialize(resp)
	}

	// Create a tools/list request (not tools/call, so no security check)
	req, err := jsonrpc.NewRequest("tools/list", nil, 1)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	data, _ := jsonrpc.Serialize(req)

	// Route the message
	response, err := r.RouteMessage(data)
	if err != nil {
		t.Fatalf("RouteMessage failed: %v", err)
	}

	// Parse response
	resp, err := jsonrpc.Parse(response)
	if err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify it's a success response
	if resp.Error != nil {
		t.Errorf("expected success response, got error: %v", resp.Error)
	}

	// Check stats
	received, forwarded, blocked, errs := r.GetStats()
	if received != 1 {
		t.Errorf("expected 1 received, got %d", received)
	}
	if forwarded != 1 {
		t.Errorf("expected 1 forwarded, got %d", forwarded)
	}
	if blocked != 0 {
		t.Errorf("expected 0 blocked, got %d", blocked)
	}
	if errs != 0 {
		t.Errorf("expected 0 errors, got %d", errs)
	}
}

func TestRouteMessage_ToolCall(t *testing.T) {
	mt := &mockTransport{}
	s := sentinel.NewClient()
	r := New(mt, s)

	// Mock forward function
	r.forwardFunc = func(data []byte) ([]byte, error) {
		resp, _ := jsonrpc.NewResponse(json.RawMessage(`1`), map[string]string{"result": "success"})
		return jsonrpc.Serialize(resp)
	}

	// Create a tools/call request
	params := map[string]interface{}{
		"name":      "read_file",
		"arguments": map[string]string{"path": "/tmp/test.txt"},
	}
	req, err := jsonrpc.NewRequest("tools/call", params, 1)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	data, _ := jsonrpc.Serialize(req)

	// Route the message (should pass with stub sentinel)
	response, err := r.RouteMessage(data)
	if err != nil {
		t.Fatalf("RouteMessage failed: %v", err)
	}

	// Parse response
	resp, err := jsonrpc.Parse(response)
	if err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify success
	if resp.Error != nil {
		t.Errorf("expected success response, got error: %v", resp.Error)
	}
}

func TestRouteMessage_InvalidJSON(t *testing.T) {
	mt := &mockTransport{}
	s := sentinel.NewClient()
	r := New(mt, s)

	// Send invalid JSON
	response, err := r.RouteMessage([]byte(`{invalid json`))
	if err != nil {
		t.Fatalf("RouteMessage should not error for invalid JSON: %v", err)
	}

	// Should get an error response
	resp, err := jsonrpc.Parse(response)
	if err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if resp.Error == nil {
		t.Error("expected error response for invalid JSON")
	}

	if resp.Error.Code != jsonrpc.ParseError {
		t.Errorf("expected ParseError code %d, got %d", jsonrpc.ParseError, resp.Error.Code)
	}

	// Check stats
	_, _, _, errs := r.GetStats()
	if errs != 1 {
		t.Errorf("expected 1 error, got %d", errs)
	}
}

func TestRouteMessage_ForwardError(t *testing.T) {
	mt := &mockTransport{}
	s := sentinel.NewClient()
	r := New(mt, s)

	// Mock forward function to return error
	r.forwardFunc = func(data []byte) ([]byte, error) {
		return nil, errors.New("connection failed")
	}

	req, _ := jsonrpc.NewRequest("ping", nil, 1)
	data, _ := jsonrpc.Serialize(req)

	_, err := r.RouteMessage(data)
	if err == nil {
		t.Error("expected error when forward fails")
	}
}

func TestRouteMessage_HighRiskTool(t *testing.T) {
	mt := &mockTransport{}
	s := sentinel.NewClient()
	r := New(mt, s)

	r.forwardFunc = func(data []byte) ([]byte, error) {
		resp, _ := jsonrpc.NewResponse(json.RawMessage(`1`), "ok")
		return jsonrpc.Serialize(resp)
	}

	// Test a high-risk tool (execute_command)
	params := map[string]interface{}{
		"name":      "execute_command",
		"arguments": map[string]string{"command": "ls"},
	}
	req, _ := jsonrpc.NewRequest("tools/call", params, 1)
	data, _ := jsonrpc.Serialize(req)

	// Should still pass with stub sentinel
	response, err := r.RouteMessage(data)
	if err != nil {
		t.Fatalf("RouteMessage failed: %v", err)
	}

	resp, _ := jsonrpc.Parse(response)
	if resp.Error != nil {
		t.Errorf("expected success with stub sentinel, got error: %v", resp.Error)
	}
}

func TestIsHighRiskTool(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"execute_command", true},
		{"write_file", true},
		{"delete_file", true},
		{"run_script", true},
		{"sudo", true},
		{"shell", true},
		{"read_file", false},
		{"list_directory", false},
		{"ping", false},
	}

	for _, tt := range tests {
		result := isHighRiskTool(tt.name)
		if result != tt.expected {
			t.Errorf("isHighRiskTool(%q) = %v, expected %v", tt.name, result, tt.expected)
		}
	}
}

func TestEstimateGas(t *testing.T) {
	tests := []struct {
		name     string
		expected uint64
	}{
		{"read_file", 100},
		{"write_file", 500},
		{"execute_command", 1000},
		{"list_directory", 50},
		{"unknown_tool", 200}, // default
	}

	for _, tt := range tests {
		result := estimateGas(tt.name)
		if result != tt.expected {
			t.Errorf("estimateGas(%q) = %d, expected %d", tt.name, result, tt.expected)
		}
	}
}

func TestGenerateSessionID(t *testing.T) {
	id1 := generateSessionID()
	id2 := generateSessionID()

	if id1 == "" {
		t.Error("generateSessionID returned empty string")
	}
	if id1 == id2 {
		t.Error("generateSessionID should return unique IDs")
	}
}

func TestNewWithConfig(t *testing.T) {
	mt := &mockTransport{}
	s := sentinel.NewClient()
	cfg := &Config{
		SessionID:    "test-session",
		GasBudget:    500000,
		MaxCallDepth: 5,
	}

	r := NewWithConfig(mt, s, cfg)

	if r.sessionID != "test-session" {
		t.Errorf("expected sessionID 'test-session', got %q", r.sessionID)
	}
}
