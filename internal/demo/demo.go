// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package demo synthesizes virtual, config-only endpoints merged into every
// account's endpoint list when the account's showDemoEndpoints toggle is on
// (port of src/demo-endpoints/). They are never persisted; config is the
// source of truth.
package demo

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/store"
)

// IDPrefix marks a virtual demo endpoint id (DEMO_ENDPOINT_ID_PREFIX).
const IDPrefix = "demo:"

// IsID reports whether id names a demo endpoint.
func IsID(id string) bool {
	return len(id) >= len(IDPrefix) && id[:len(IDPrefix)] == IDPrefix
}

// bakedInHostKeys pins the public demo hosts' SSH keys so a demo endpoint
// against them never goes through trust-on-first-use (#241). Keyed by host;
// values are OpenSSH public-key lines. A config hostKey on the demo endpoint
// takes precedence. NOTE(#241): the ssh.shellwatch.ai entry must be filled in
// with the real host key before the public demo ships.
var bakedInHostKeys = map[string]string{
	// "ssh.shellwatch.ai": "ssh-ed25519 AAAA... shellwatch-demo",
}

// HostKey is a demo endpoint's pinned host key. Demo endpoints are virtual
// (never persisted), so their pins live here: provisioned from config or the
// baked-in table, or — failing both — pinned in process memory on the first
// approved connection.
type HostKey struct {
	Type        string
	Key         []byte
	Fingerprint string
	PinnedBy    string // "config", "demo" (baked-in), or the approval identity
}

// Service lists synthesized demo endpoints from config.
type Service struct {
	endpoints []config.SeedEndpoint

	pinsMu sync.Mutex
	pins   map[string]HostKey // endpoint id -> pin
}

func NewService(endpoints []config.SeedEndpoint) *Service {
	s := &Service{endpoints: endpoints, pins: map[string]HostKey{}}
	for _, e := range endpoints {
		id := stableID(e.Parsed.Host, e.Parsed.Port, e.Parsed.Username)
		if hk := e.ParsedHostKey; hk != nil {
			s.pins[id] = HostKey{Type: hk.Type, Key: hk.Key, Fingerprint: hk.Fingerprint, PinnedBy: "config"}
			continue
		}
		if line, ok := bakedInHostKeys[e.Parsed.Host]; ok {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				slog.Warn("demo: invalid baked-in host key, skipping", "host", e.Parsed.Host, "err", err)
				continue
			}
			s.pins[id] = HostKey{Type: key.Type(), Key: key.Marshal(), Fingerprint: ssh.FingerprintSHA256(key), PinnedBy: "demo"}
		}
	}
	return s
}

// HostKeyFor returns the pin for a demo endpoint id (ok=false when unpinned).
func (s *Service) HostKeyFor(endpointID string) (HostKey, bool) {
	s.pinsMu.Lock()
	defer s.pinsMu.Unlock()
	hk, ok := s.pins[endpointID]
	return hk, ok
}

// PinHostKey records an approval-driven pin for a demo endpoint in process
// memory (compare-and-set like the persistent store): demo endpoints are
// virtual, so a TOFU pin lives for the process lifetime.
func (s *Service) PinHostKey(endpointID string, hk HostKey) error {
	s.pinsMu.Lock()
	defer s.pinsMu.Unlock()
	if existing, ok := s.pins[endpointID]; ok {
		if existing.Fingerprint == hk.Fingerprint {
			return nil
		}
		return store.ErrHostKeyPinned
	}
	s.pins[endpointID] = hk
	return nil
}

// stableID derives a restart-stable id from the address tuple (demoEndpointId).
func stableID(host string, port int, username string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s %d %s", host, port, username)))
	return IDPrefix + base64.RawURLEncoding.EncodeToString(sum[:])[:12]
}

// List returns the synthesized endpoints for the requesting account.
func (s *Service) List(accountID string) []store.Endpoint {
	out := make([]store.Endpoint, 0, len(s.endpoints))
	for _, e := range s.endpoints {
		id := stableID(e.Parsed.Host, e.Parsed.Port, e.Parsed.Username)
		var pin *store.HostKeyPin
		if hk, ok := s.HostKeyFor(id); ok {
			pin = &store.HostKeyPin{Type: hk.Type, Fingerprint: hk.Fingerprint, PinnedBy: hk.PinnedBy}
		}
		out = append(out, store.Endpoint{
			ID:               id,
			AccountID:        accountID,
			Label:            e.Label,
			Host:             e.Parsed.Host,
			Port:             int64(e.Parsed.Port),
			Username:         e.Parsed.Username,
			UserVerification: "required",
			Description:      e.Description,
			AgentForward:     e.AgentForwardEnabled(),
			HostKey:          pin,
		})
	}
	return out
}

// IsEmpty reports whether the operator configured no demo endpoints (drives the
// UI's demoEndpointsAvailable flag).
func (s *Service) IsEmpty() bool { return len(s.endpoints) == 0 }
