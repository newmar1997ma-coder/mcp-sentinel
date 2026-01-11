// Package transport handles MCP protocol transports.
//
// It provides implementations for the two primary MCP transport modes:
//
//   - Stdio: Communication via standard input/output (subprocess model)
//   - SSE: Server-Sent Events over HTTP (remote server model)
//
// # Transport Interface
//
// All transports implement the Transport interface, allowing the proxy
// router to work with any transport type interchangeably.
//
// # Message Framing
//
// Stdio transport uses newline-delimited JSON (NDJSON).
// SSE transport uses standard SSE framing with "data:" prefix.
//
// # Security Notes
//
// Transports are responsible for:
//   - Proper message framing (preventing message injection)
//   - Clean connection lifecycle management
//   - Timeout handling to prevent hanging
package transport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Common transport errors.
var (
	ErrClosed         = errors.New("transport: connection closed")
	ErrTimeout        = errors.New("transport: operation timed out")
	ErrInvalidMessage = errors.New("transport: invalid message format")
)

// Transport defines the interface for MCP communication.
//
// Implementations must be safe for concurrent use.
type Transport interface {
	// Send transmits a message to the remote endpoint.
	// The message should be a complete JSON-RPC message.
	Send(data []byte) error

	// Receive reads the next message from the remote endpoint.
	// Blocks until a message is available or an error occurs.
	Receive() ([]byte, error)

	// Close terminates the transport connection.
	// After Close, Send and Receive will return ErrClosed.
	Close() error
}

// StdioTransport implements Transport over stdin/stdout.
//
// This is the standard transport for local MCP servers running as
// subprocesses. Messages are newline-delimited JSON (NDJSON).
//
// # Thread Safety
//
// StdioTransport is safe for concurrent Send and Receive calls.
// However, only one goroutine should call Receive at a time.
type StdioTransport struct {
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	scanner *bufio.Scanner
	mu      sync.Mutex
	closed  bool
}

// NewStdioTransport creates a new stdio transport.
//
// Uses os.Stdin for reading and os.Stdout for writing by default.
// For testing or subprocess communication, use NewStdioTransportWithPipes.
func NewStdioTransport() *StdioTransport {
	return NewStdioTransportWithPipes(os.Stdout, os.Stdin)
}

// NewStdioTransportWithPipes creates a stdio transport with custom pipes.
//
// # Arguments
//   - stdin: Writer for sending messages (connected to subprocess stdin)
//   - stdout: Reader for receiving messages (connected to subprocess stdout)
//
// Note: The naming follows the perspective of the subprocess:
// we write to its stdin and read from its stdout.
func NewStdioTransportWithPipes(stdin io.WriteCloser, stdout io.ReadCloser) *StdioTransport {
	scanner := bufio.NewScanner(stdout)
	// Allow larger messages (default is 64KB, MCP can have larger payloads)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB max

	return &StdioTransport{
		stdin:   stdin,
		stdout:  stdout,
		scanner: scanner,
	}
}

// Send writes a message to the subprocess stdin.
//
// The message is written as a single line followed by a newline.
// Any embedded newlines in the message will cause protocol errors.
func (t *StdioTransport) Send(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrClosed
	}

	// Validate no embedded newlines
	if bytes.Contains(data, []byte("\n")) {
		return fmt.Errorf("%w: message contains embedded newline", ErrInvalidMessage)
	}

	// Write message with newline terminator
	if _, err := t.stdin.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("transport: write failed: %w", err)
	}

	return nil
}

// Receive reads the next message from the subprocess stdout.
//
// Blocks until a complete line is available. Returns ErrClosed if
// the transport has been closed or EOF is reached.
func (t *StdioTransport) Receive() ([]byte, error) {
	if t.closed {
		return nil, ErrClosed
	}

	if t.scanner.Scan() {
		return t.scanner.Bytes(), nil
	}

	if err := t.scanner.Err(); err != nil {
		return nil, fmt.Errorf("transport: read failed: %w", err)
	}

	return nil, ErrClosed // EOF
}

// Close terminates the stdio transport.
//
// Closes both stdin and stdout pipes. Safe to call multiple times.
func (t *StdioTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	var errs []error
	if err := t.stdin.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := t.stdout.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("transport: close errors: %v", errs)
	}
	return nil
}

// SSETransport implements Transport over HTTP Server-Sent Events.
//
// This transport is used for remote MCP servers accessible via HTTP.
// Outgoing messages are sent as POST requests, incoming messages arrive
// as SSE events.
//
// # Architecture
//
// The SSE transport maintains:
//   - An HTTP client for sending POST requests
//   - An SSE connection for receiving events
//   - A message channel for buffering received messages
//
// # Security Notes
//
// SSE connections should use HTTPS in production to prevent MITM attacks.
type SSETransport struct {
	baseURL    string
	client     *http.Client
	messages   chan []byte
	errors     chan error
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
	connected  bool
}

// NewSSETransport creates a new SSE transport.
//
// # Arguments
//   - baseURL: Base URL of the MCP server (e.g., "http://localhost:8080")
//
// The transport will:
//   - POST to {baseURL}/message for sending
//   - Connect to {baseURL}/sse for receiving
func NewSSETransport(baseURL string) *SSETransport {
	ctx, cancel := context.WithCancel(context.Background())

	return &SSETransport{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		client:   &http.Client{Timeout: 30 * time.Second},
		messages: make(chan []byte, 100),
		errors:   make(chan error, 1),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Connect establishes the SSE connection for receiving messages.
//
// This should be called before Receive. The connection runs in a
// background goroutine until Close is called.
func (t *SSETransport) Connect() error {
	t.mu.Lock()
	if t.connected {
		t.mu.Unlock()
		return nil
	}
	t.connected = true
	t.mu.Unlock()

	go t.readLoop()
	return nil
}

// readLoop handles the SSE connection and parses incoming events.
func (t *SSETransport) readLoop() {
	req, err := http.NewRequestWithContext(t.ctx, "GET", t.baseURL+"/sse", nil)
	if err != nil {
		t.errors <- fmt.Errorf("transport: failed to create SSE request: %w", err)
		return
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := t.client.Do(req)
	if err != nil {
		t.errors <- fmt.Errorf("transport: SSE connection failed: %w", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.errors <- fmt.Errorf("transport: SSE returned status %d", resp.StatusCode)
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	var dataBuffer bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()

		// SSE format: "data: <json>\n\n"
		if strings.HasPrefix(line, "data: ") {
			dataBuffer.WriteString(strings.TrimPrefix(line, "data: "))
		} else if line == "" && dataBuffer.Len() > 0 {
			// Empty line marks end of event
			select {
			case t.messages <- bytes.Clone(dataBuffer.Bytes()):
			case <-t.ctx.Done():
				return
			}
			dataBuffer.Reset()
		}
	}

	if err := scanner.Err(); err != nil {
		select {
		case t.errors <- fmt.Errorf("transport: SSE read error: %w", err):
		default:
		}
	}
}

// Send transmits a message to the MCP server via HTTP POST.
//
// The message is sent as the request body with content-type application/json.
func (t *SSETransport) Send(data []byte) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	t.mu.Unlock()

	req, err := http.NewRequestWithContext(t.ctx, "POST", t.baseURL+"/message", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("transport: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("transport: POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("transport: server returned status %d", resp.StatusCode)
	}

	return nil
}

// Receive reads the next message from the SSE stream.
//
// Blocks until a message is available. Call Connect before Receive.
func (t *SSETransport) Receive() ([]byte, error) {
	select {
	case msg := <-t.messages:
		return msg, nil
	case err := <-t.errors:
		return nil, err
	case <-t.ctx.Done():
		return nil, ErrClosed
	}
}

// Close terminates the SSE transport.
//
// Cancels the SSE connection and cleans up resources.
func (t *SSETransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true
	t.cancel()

	return nil
}
