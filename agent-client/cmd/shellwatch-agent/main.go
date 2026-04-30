// shellwatch-agent is a thin SSH agent proxy that relays SSH agent
// protocol requests from a local Unix socket to a remote ShellWatch
// server over WebSocket.
//
// First-time setup (recommended): run `shellwatch-agent login` once to
// obtain an `agent`-scoped API key via the browser-based OAuth flow.
// The token is stored in the OS keyring (or a 0600 file fallback) and
// the agent daemon picks it up automatically on subsequent runs.
//
// Usage:
//
//	# One-time browser-based login. Token persists per server URL.
//	shellwatch-agent login [--server URL] [--insecure]
//
//	# Remove the locally-stored token. Does not revoke the API key
//	# server-side — for that, delete it in Settings → API Keys.
//	shellwatch-agent logout [--server URL]
//
//	# Default daemon mode (no subcommand). Picks up the token from
//	# --api-key, SHELLWATCH_API_KEY, or the credstore (in that order).
//	shellwatch-agent [--server URL] [--socket PATH] [--insecure]
//
//	# Print export line for shell rc files.
//	eval $(shellwatch-agent --print-env)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/rado0x54/shellwatch-agent/internal/config"
	"github.com/rado0x54/shellwatch-agent/internal/credstore"
	"github.com/rado0x54/shellwatch-agent/internal/oauth"
	"github.com/rado0x54/shellwatch-agent/internal/proxy"
)

// Version is set at build time via -ldflags "-X main.Version=..."
// Defaults to "dev" for plain `go build` / `go run`.
var Version = "dev"

func main() {
	// Subcommand dispatch happens before the daemon's flag parsing so
	// `shellwatch-agent login --server X` doesn't trip over the daemon's
	// flagset. Anything not matched here falls through to the daemon path.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "login":
			exitOn(runLogin(os.Args[2:]))
			return
		case "logout":
			exitOn(runLogout(os.Args[2:]))
			return
		case "version", "--version", "-v":
			fmt.Println(Version)
			return
		case "help", "--help", "-h":
			printUsage(os.Stdout)
			return
		}
	}
	exitOn(runDaemon())
}

// runDaemon is the historical entry point — relay the SSH agent socket
// over WebSocket. Now also picks up its API key from the credstore when
// no flag/env was given.
func runDaemon() error {
	cfg, printEnv, err := config.Load()
	if err != nil {
		return err
	}
	if printEnv {
		// Windows users running PowerShell can `iex (shellwatch-agent --print-env)`;
		// bash/zsh/fish all accept `eval "$(shellwatch-agent --print-env)"`.
		if runtime.GOOS == "windows" {
			fmt.Printf("$env:SSH_AUTH_SOCK = '%s'\n", cfg.SocketPath)
		} else {
			fmt.Printf("export SSH_AUTH_SOCK=%s\n", cfg.SocketPath)
		}
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	return proxy.Run(proxy.ProxyConfig{
		SocketPath: cfg.SocketPath,
		ServerURL:  cfg.Server,
		ApiKey:     cfg.ApiKey,
		Insecure:   cfg.Insecure,
		Version:    Version,
	})
}

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	server := fs.String("server", "", "ShellWatch server URL (defaults to $SHELLWATCH_SERVER or "+config.DefaultServer+")")
	insecure := fs.Bool("insecure", false, "Allow http:// — local dev only; never use against production")
	if err := fs.Parse(args); err != nil {
		return err
	}

	serverURL := resolveServer(*server)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	result, err := oauth.Login(ctx, oauth.LoginOptions{
		ServerURL:     serverURL,
		Scope:         "agent",
		AllowInsecure: *insecure,
		Stdout:        os.Stdout,
	})
	if err != nil {
		return err
	}

	store, err := credstore.New()
	if err != nil {
		return fmt.Errorf("open credential store: %w", err)
	}
	if err := store.Set(result.ServerURL, result.AccessToken); err != nil {
		return fmt.Errorf("save credential: %w", err)
	}

	fmt.Fprintf(os.Stdout, "\nOK: authorized for %s\n", result.ServerURL)
	fmt.Fprintf(os.Stdout, "  Token saved. The agent daemon will pick it up automatically.\n")
	return nil
}

func runLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	server := fs.String("server", "", "ShellWatch server URL (defaults to $SHELLWATCH_SERVER or "+config.DefaultServer+")")
	if err := fs.Parse(args); err != nil {
		return err
	}

	serverURL := resolveServer(*server)

	store, err := credstore.New()
	if err != nil {
		return fmt.Errorf("open credential store: %w", err)
	}
	if err := store.Delete(serverURL); err != nil {
		if errors.Is(err, credstore.ErrNotFound) {
			fmt.Fprintf(os.Stdout, "No stored credential for %s.\n", serverURL)
			return nil
		}
		return fmt.Errorf("delete credential: %w", err)
	}

	fmt.Fprintf(os.Stdout, "OK: removed local token for %s.\n", serverURL)
	fmt.Fprintf(os.Stdout, "  Note: the API key still exists server-side. To revoke it entirely,\n")
	fmt.Fprintf(os.Stdout, "  delete it in Settings → API Keys at %s.\n", serverURL)
	return nil
}

// resolveServer applies precedence: explicit flag > env > default.
func resolveServer(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("SHELLWATCH_SERVER"); env != "" {
		return env
	}
	return config.DefaultServer
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `shellwatch-agent — thin SSH agent proxy for ShellWatch

USAGE
  shellwatch-agent <command> [flags]
  shellwatch-agent [flags]                    # daemon mode

COMMANDS
  login     Authorize this device via the browser. Stores an agent-scoped
            API key in the OS keyring (or a 0600 file fallback).
  logout    Remove the locally-stored token. Does not revoke the API key
            server-side — see Settings → API Keys for that.
  version   Print build version.
  help      Print this help.

DAEMON FLAGS
  --server URL          ShellWatch server (default: $SHELLWATCH_SERVER or
                        ` + config.DefaultServer + `)
  --api-key KEY         Static API key. Skips the credstore lookup.
  --socket PATH         Listener path. On macOS/Linux, a Unix socket
                        ($XDG_RUNTIME_DIR/shellwatch-agent.sock or a
                        per-user path under $TMPDIR by default).
                        On Windows, a named pipe (default
                        \\.\pipe\openssh-ssh-agent so stock OpenSSH
                        for Windows finds the proxy automatically).
  --insecure            Allow ws:// (no TLS). Local dev only.
  --print-env           Print 'export SSH_AUTH_SOCK=...' and exit.

LOGIN FLAGS
  --server URL          Which ShellWatch instance to authorize against.
  --insecure            Allow http://. Local dev only.

ENVIRONMENT
  SHELLWATCH_SERVER     Default --server value.
  SHELLWATCH_API_KEY    Default --api-key value.
  SHELLWATCH_AGENT_SOCK Default --socket value.
`)
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
