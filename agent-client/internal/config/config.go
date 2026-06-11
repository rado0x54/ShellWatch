// SPDX-License-Identifier: MIT
// Package config handles configuration from CLI flags, environment variables,
// and the credstore with precedence: flags > env > credstore > defaults.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/rado0x54/shellwatch-agent/internal/credstore"
	"github.com/rado0x54/shellwatch-agent/internal/oauth"
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
	SocketPath string
	Insecure   bool
	// Token yields the bearer for /agent-proxy. Either a StaticToken (from
	// --api-key / SHELLWATCH_API_KEY, or a legacy credstore value) or a
	// ClientCredentialsSource that mints + refreshes short-lived access tokens
	// from a stored OAuth client (#217). Nil when no credential is configured.
	Token oauth.Tokener
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
		SocketPath: ev.socketPath,
		Insecure:   fv.insecure,
	}

	// A bare static bearer passed directly (an access token minted out-of-band).
	staticToken := ev.apiKey

	if fv.explicit["server"] {
		cfg.Server = fv.server
	}
	if fv.explicit["api-key"] {
		staticToken = fv.apiKey
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

	// A static token from --api-key / SHELLWATCH_API_KEY wins — used as a fixed
	// bearer (e.g. an access token you minted with curl for a quick test).
	if staticToken != "" {
		cfg.Token = oauth.StaticToken(staticToken)
		return cfg
	}

	// Otherwise consult the credstore. `shellwatch-agent login` stores the DCR
	// client id + refresh token there; the daemon mints + refreshes access
	// tokens from them and persists each rotated refresh token. A legacy raw
	// value is treated as a static bearer. Lookup-misses fall through (Validate
	// surfaces a friendly message); open/read failures get a one-line warning.
	store, err := newCredStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not open credstore: %v\n", err)
		return cfg
	}
	val, err := store.Get(cfg.Server)
	if err != nil {
		if !errors.Is(err, credstore.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "warning: credstore lookup for %s failed: %v\n", cfg.Server, err)
		}
		return cfg
	}
	if creds, ok := oauth.DecodeCreds(val); ok {
		server := cfg.Server
		clientID := creds.ClientID
		onRotate := func(refreshToken string) {
			updated, encErr := oauth.StoredCreds{ClientID: clientID, RefreshToken: refreshToken}.Encode()
			if encErr != nil {
				return
			}
			if setErr := store.Set(server, updated); setErr != nil {
				fmt.Fprintf(os.Stderr, "warning: could not persist rotated refresh token: %v\n", setErr)
			}
		}
		cfg.Token = oauth.NewRefreshTokenSource(server, clientID, creds.RefreshToken, cfg.Insecure, onRotate)
	} else {
		cfg.Token = oauth.StaticToken(val)
	}
	return cfg
}

func (c *Config) Validate() error {
	if c.Token == nil {
		return fmt.Errorf(
			"no credentials for %s — run `shellwatch-agent login --server %s` (browser passkey login), "+
				"or pass a token via SHELLWATCH_API_KEY / --api-key",
			c.Server, c.Server,
		)
	}
	return nil
}
