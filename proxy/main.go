// MCP Sentinel Proxy - High-performance Go proxy for MCP traffic
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	fmt.Println("MCP Sentinel Proxy v0.1.0")

	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("Build: development")
		return
	}

	log.Println("Starting MCP Sentinel Proxy...")
	log.Println("Proxy ready - awaiting connections")
}
