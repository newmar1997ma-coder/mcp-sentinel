// Package transport handles MCP protocol transport (stdio, HTTP, WebSocket)
package transport

// Transport defines the interface for MCP communication
type Transport interface {
	Send(data []byte) error
	Receive() ([]byte, error)
	Close() error
}

// StdioTransport implements Transport over stdio
type StdioTransport struct{}

// HTTPTransport implements Transport over HTTP/SSE
type HTTPTransport struct {
	baseURL string
}

// WebSocketTransport implements Transport over WebSocket
type WebSocketTransport struct {
	url string
}
