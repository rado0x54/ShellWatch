// Package config handles configuration from CLI flags and environment variables
// with precedence: flags > env > defaults.
package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Server     string
	ApiKey     string
	SocketPath string
	Insecure   bool
}

func defaultSocketPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "shellwatch-agent.sock")
	}
	// Use UID suffix to avoid predictable paths in shared /tmp (symlink attack vector)
	return filepath.Join(os.TempDir(), fmt.Sprintf("shellwatch-agent-%d.sock", os.Getuid()))
}

// Load reads configuration from CLI flags and environment variables.
func Load() (*Config, bool, error) {
	var (
		server     = flag.String("server", "", "ShellWatch server URL (e.g., https://shellwatch.example.com)")
		apiKey     = flag.String("api-key", "", "API key for authentication")
		socketPath = flag.String("socket", "", "Unix socket path")
		insecure   = flag.Bool("insecure", false, "Allow ws:// (unencrypted) connections")
		printEnv   = flag.Bool("print-env", false, "Print SSH_AUTH_SOCK export and exit")
	)
	flag.Parse()

	cfg := &Config{
		Server:     os.Getenv("SHELLWATCH_SERVER"),
		ApiKey:     os.Getenv("SHELLWATCH_API_KEY"),
		SocketPath: os.Getenv("SHELLWATCH_AGENT_SOCK"),
		Insecure:   *insecure,
	}

	if cfg.SocketPath == "" {
		cfg.SocketPath = defaultSocketPath()
	}

	// CLI flags override env vars
	if *server != "" {
		cfg.Server = *server
	}
	if *apiKey != "" {
		cfg.ApiKey = *apiKey
	}
	if *socketPath != "" {
		cfg.SocketPath = *socketPath
	}

	return cfg, *printEnv, nil
}

func (c *Config) Validate() error {
	if c.Server == "" {
		return fmt.Errorf("server URL is required (use --server or SHELLWATCH_SERVER)")
	}
	if c.ApiKey == "" {
		return fmt.Errorf("API key is required (use --api-key or SHELLWATCH_API_KEY)")
	}
	return nil
}
