package config

import "testing"

func TestResolveServerPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		flagServer string
		flagSet    bool
		envServer  string
		want       string
	}{
		{
			name: "no flag, no env -> default",
			want: DefaultServer,
		},
		{
			name:      "env only -> env wins",
			envServer: "https://env.example.com",
			want:      "https://env.example.com",
		},
		{
			name:       "explicit flag only -> flag wins",
			flagServer: "https://flag.example.com",
			flagSet:    true,
			want:       "https://flag.example.com",
		},
		{
			name:       "explicit flag overrides env",
			flagServer: "https://flag.example.com",
			flagSet:    true,
			envServer:  "https://env.example.com",
			want:       "https://flag.example.com",
		},
		{
			name:       "default-valued flag does not clobber env",
			flagServer: DefaultServer, // matches the default; flag.Visit would not report it
			flagSet:    false,
			envServer:  "https://env.example.com",
			want:       "https://env.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := flagValues{
				server:   tt.flagServer,
				explicit: map[string]bool{},
			}
			if tt.flagSet {
				fv.explicit["server"] = true
			}
			ev := envValues{server: tt.envServer}

			cfg := resolve(fv, ev)
			if cfg.Server != tt.want {
				t.Errorf("Server = %q, want %q", cfg.Server, tt.want)
			}
		})
	}
}

func TestResolveApiKeyPrecedence(t *testing.T) {
	// explicit flag overrides env
	cfg := resolve(
		flagValues{apiKey: "from-flag", explicit: map[string]bool{"api-key": true}},
		envValues{apiKey: "from-env"},
	)
	if cfg.ApiKey != "from-flag" {
		t.Errorf("ApiKey = %q, want from-flag", cfg.ApiKey)
	}

	// env used when flag not set
	cfg = resolve(
		flagValues{explicit: map[string]bool{}},
		envValues{apiKey: "from-env"},
	)
	if cfg.ApiKey != "from-env" {
		t.Errorf("ApiKey = %q, want from-env", cfg.ApiKey)
	}
}

func TestValidateRequiresApiKey(t *testing.T) {
	if err := (&Config{Server: DefaultServer}).Validate(); err == nil {
		t.Fatal("expected error for missing API key")
	}
	if err := (&Config{Server: DefaultServer, ApiKey: "k"}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
