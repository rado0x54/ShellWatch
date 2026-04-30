// Package config handles configuration from CLI flags, environment variables,
// and the credstore with precedence: flags > env > credstore > defaults.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/rado0x54/shellwatch-agent/internal/credstore"
)

// DefaultServer is the hosted ShellWatch instance, used when neither
// --server nor SHELLWATCH_SERVER is set.
const DefaultServer = "https://app.shellwatch.ai"

// newCredStore is the package-level seam tests use to inject a fake
// credstore. Production callers get the real OS keyring + file fallback;
// `config_test.go` swaps it for an empty in-memory store via TestMain so
// `TestResolve*` never reads (or prints warnings about) a developer's
// actual saved tokens.
var newCredStore = credstore.New

type Config struct {
	Server     string
	ApiKey     string
	SocketPath string
	Insecure   bool
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
	// Lookup-misses (no token saved yet) fall through silently so
	// Validate() can surface a friendlier "no API key for X" message;
	// open/read failures (broken HOME, unreadable file) get a one-line
	// warning to stderr so the user has a hint when "no API key" is
	// hiding a real problem.
	if cfg.ApiKey == "" {
		store, err := newCredStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not open credstore: %v\n", err)
		} else {
			token, err := store.Get(cfg.Server)
			if err == nil {
				cfg.ApiKey = token
			} else if !errors.Is(err, credstore.ErrNotFound) {
				fmt.Fprintf(os.Stderr, "warning: credstore lookup for %s failed: %v\n", cfg.Server, err)
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
