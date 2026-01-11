// MCP Sentinel Proxy - High-performance Go proxy for MCP traffic
//
// This is the main entry point for the MCP Sentinel Proxy.
// It intercepts MCP JSON-RPC traffic and routes it through
// security checks via Rust FFI before forwarding to servers.
//
// Usage:
//
//	mcp-sentinel-proxy                  # Start in stdio mode
//	mcp-sentinel-proxy --mode=sse       # Start in SSE mode
//	mcp-sentinel-proxy version          # Print version
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

// Version information set at build time.
var (
	Version   = "0.1.0"
	BuildTime = "development"
)

func main() {
	// Parse flags
	mode := flag.String("mode", "stdio", "Transport mode: stdio or sse")
	port := flag.Int("port", 8080, "Port for SSE mode")
	flag.Parse()

	// Handle version command
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("MCP Sentinel Proxy v%s\n", Version)
		fmt.Printf("Build: %s\n", BuildTime)
		return
	}

	log.Printf("MCP Sentinel Proxy v%s starting...", Version)
	log.Printf("Transport mode: %s", *mode)

	switch *mode {
	case "stdio":
		log.Println("Starting stdio transport...")
		// TODO: Initialize StdioTransport and Router
		log.Println("Proxy ready - reading from stdin")
	case "sse":
		log.Printf("Starting SSE transport on port %d...", *port)
		// TODO: Initialize SSETransport and Router
		log.Printf("Proxy ready - listening on :%d", *port)
	default:
		log.Fatalf("Unknown transport mode: %s", *mode)
	}

	// Block forever (actual implementation will have event loop)
	select {}
}
