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

	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/store"
)

// IDPrefix marks a virtual demo endpoint id (DEMO_ENDPOINT_ID_PREFIX).
const IDPrefix = "demo:"

// IsID reports whether id names a demo endpoint.
func IsID(id string) bool {
	return len(id) >= len(IDPrefix) && id[:len(IDPrefix)] == IDPrefix
}

// Service lists synthesized demo endpoints from config.
type Service struct {
	endpoints []config.SeedEndpoint
}

func NewService(endpoints []config.SeedEndpoint) *Service {
	return &Service{endpoints: endpoints}
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
		out = append(out, store.Endpoint{
			ID:               stableID(e.Parsed.Host, e.Parsed.Port, e.Parsed.Username),
			AccountID:        accountID,
			Label:            e.Label,
			Host:             e.Parsed.Host,
			Port:             int64(e.Parsed.Port),
			Username:         e.Parsed.Username,
			UserVerification: "required",
			Description:      e.Description,
			AgentForward:     e.AgentForwardEnabled(),
		})
	}
	return out
}
