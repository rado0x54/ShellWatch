// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package hostkeys implements sshx.HostKeys (#241) over the two pin stores:
// the endpoints table for persistent endpoints and the demo service's
// in-memory pins for virtual demo endpoints. Pin writes are compare-and-set
// in both stores; a successful pin flags the approving action in the audit
// log via OnPinned.
package hostkeys

import (
	"context"
	"fmt"

	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/sshx"
	"github.com/rado0x54/shellwatch/internal/store"
)

// Service routes pin lookups/writes to the right store.
type Service struct {
	Endpoints *store.Endpoints
	Demo      *demo.Service // nil when no demo endpoints are configured
	// OnPinned flags the approval action that pinned a key (audit); may be nil.
	OnPinned func(actionID string)
}

var _ sshx.HostKeys = (*Service)(nil)

// Lookup returns the pin for an endpoint id (nil when unpinned).
func (s *Service) Lookup(ctx context.Context, endpointID string) (*sshx.PinnedHostKey, error) {
	if demo.IsID(endpointID) {
		if s.Demo == nil {
			return nil, nil
		}
		hk, ok := s.Demo.HostKeyFor(endpointID)
		if !ok {
			return nil, nil
		}
		return &sshx.PinnedHostKey{Type: hk.Type, Key: hk.Key, Fingerprint: hk.Fingerprint}, nil
	}
	rec, err := s.Endpoints.GetHostKey(ctx, endpointID)
	if err != nil || rec == nil {
		return nil, err
	}
	return &sshx.PinnedHostKey{Type: rec.Type, Key: rec.Key, Fingerprint: rec.Fingerprint}, nil
}

// Pin compare-and-set-persists an observed key as the endpoint's pin, bound
// to the address the observing connection dialed (req.Host/req.Port).
func (s *Service) Pin(ctx context.Context, req sshx.PinRequest) error {
	if demo.IsID(req.EndpointID) {
		if s.Demo == nil {
			return fmt.Errorf("unknown demo endpoint %s", req.EndpointID)
		}
		// Demo ids are derived from the address tuple (demo.stableID), so the
		// pin is address-bound by construction: a different address is a
		// different demo endpoint id.
		if err := s.Demo.PinHostKey(req.EndpointID, demo.HostKey{
			Type: req.Observed.Type, Key: req.Observed.Key, Fingerprint: req.Observed.Fingerprint, PinnedBy: req.PinnedBy,
		}); err != nil {
			return err
		}
	} else {
		if err := s.Endpoints.PinHostKey(ctx, store.PinHostKeyParams{
			ID: req.EndpointID, Host: req.Host, Port: req.Port,
			Record:   store.HostKeyRecord{Type: req.Observed.Type, Key: req.Observed.Key, Fingerprint: req.Observed.Fingerprint},
			PinnedBy: req.PinnedBy,
		}); err != nil {
			return err
		}
	}
	if s.OnPinned != nil {
		s.OnPinned(req.ActionID)
	}
	return nil
}
