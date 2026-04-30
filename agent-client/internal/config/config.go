// Package config handles configuration from CLI flags, environment variables,
// and the credstore with precedence: flags > env > credstore > defaults.
package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rado0x54/shellwatch-agent/internal/credstore"
)

// DefaultServer is the hosted ShellWatch instance, used when neither
// --server nor SHELLWATCH_SERVER is set.
const DefaultServer = "https://app.shellwatch.ai"

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

// flagValues holds the parsed flag inputs along with which flags the user
// actually set on the command line — needed to distinguish "user passed
// --server=https://app.shellwatch.ai" from "flag was left at its default".
type flagValues struct {
	server     string
	apiKey     string
	socketPath string
	insecure   bool
	printEnv   bool
	explicit   map[string]bool
}

// envValues holds the relevant environment variables.
type envValues struct {
	server     string
	apiKey     string
	socketPath string
}

// Load reads configuration from CLI flags and environment variables.
func Load() (*Config, bool, error) {
	fv := parseFlags()
	ev := envValues{
		server:     os.Getenv("SHELLWATCH_SERVER"),
		apiKey:     os.Getenv("SHELLWATCH_API_KEY"),
		socketPath: os.Getenv("SHELLWATCH_AGENT_SOCK"),
	}
	cfg := resolve(fv, ev)
	return cfg, fv.printEnv, nil
}

func parseFlags() flagValues {
	server := flag.String("server", DefaultServer, "ShellWatch server URL")
	apiKey := flag.String("api-key", "", "API key for authentication")
	socketPath := flag.String("socket", "", "Unix socket path")
	insecure := flag.Bool("insecure", false, "Allow ws:// (unencrypted) connections")
	printEnv := flag.Bool("print-env", false, "Print SSH_AUTH_SOCK export and exit")
	flag.Parse()

	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	return flagValues{
		server:     *server,
		apiKey:     *apiKey,
		socketPath: *socketPath,
		insecure:   *insecure,
		printEnv:   *printEnv,
		explicit:   explicit,
	}
}

// resolve merges flags and env into a Config with precedence: explicit flag > env > default.
func resolve(fv flagValues, ev envValues) *Config {
	cfg := &Config{
		Server:     ev.server,
		ApiKey:     ev.apiKey,
		SocketPath: ev.socketPath,
		Insecure:   fv.insecure,
	}

	if fv.explicit["server"] {
		cfg.Server = fv.server
	}
	if fv.explicit["api-key"] {
		cfg.ApiKey = fv.apiKey
	}
	if fv.explicit["socket"] {
		cfg.SocketPath = fv.socketPath
	}

	if cfg.Server == "" {
		cfg.Server = DefaultServer
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = defaultSocketPath()
	}

	// Final fallback for ApiKey: consult the credstore. Lets users run
	// `shellwatch-agent login` once and have the daemon pick up the token
	// automatically — no env var, no flag, no plaintext config file.
	// Failures are silent on purpose; Validate() surfaces a friendlier
	// message than "couldn't open credstore".
	if cfg.ApiKey == "" {
		if store, err := credstore.New(); err == nil {
			if token, err := store.Get(cfg.Server); err == nil {
				cfg.ApiKey = token
			}
		}
	}

	return cfg
}

func (c *Config) Validate() error {
	if c.ApiKey == "" {
		return fmt.Errorf(
			"no API key for %s — run `shellwatch-agent login --server %s` to authorize, "+
				"or set SHELLWATCH_API_KEY / pass --api-key",
			c.Server, c.Server,
		)
	}
	return nil
}
