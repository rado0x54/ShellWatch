// shellwatch-agent is a thin SSH agent proxy that relays SSH agent
// protocol requests from a local Unix socket to a remote ShellWatch
// server over WebSocket.
//
// Usage:
//
//	shellwatch-agent --server https://shellwatch.example.com --api-key sw_...
//	eval $(shellwatch-agent --print-env)
//	ssh-add -l  # lists ShellWatch keys
//	ssh user@host  # authenticates via ShellWatch
package main

import (
	"fmt"
	"os"

	"github.com/rado0x54/shellwatch-agent/internal/config"
	"github.com/rado0x54/shellwatch-agent/internal/proxy"
)

// Version is set at build time via -ldflags "-X main.Version=..."
// Defaults to "dev" for plain `go build` / `go run`.
var Version = "dev"

func main() {
	cfg, printEnv, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if printEnv {
		fmt.Printf("export SSH_AUTH_SOCK=%s\n", cfg.SocketPath)
		os.Exit(0)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := proxy.Run(proxy.ProxyConfig{
		SocketPath: cfg.SocketPath,
		ServerURL:  cfg.Server,
		ApiKey:     cfg.ApiKey,
		Insecure:   cfg.Insecure,
		Version:    Version,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
