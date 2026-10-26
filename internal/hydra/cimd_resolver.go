// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// CIMD → Hydra provisioning: turn a resolved Client ID Metadata Document into
// a Hydra client whose client_id IS the Client Identifier URL, so Hydra's
// authorize / token / refresh / revoke / introspect paths all work unchanged.
//
// Ownership rule: ShellWatch only ever writes a client it created itself from
// CIMD, marked by metadata.shellwatch.origin == "cimd". An admin- or
// DCR-created client that happens to use a URL id keeps its registration.
package hydra

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/rado0x54/shellwatch/internal/clock"
)

// OriginCIMD marks clients provisioned from a Client ID Metadata Document.
const OriginCIMD = "cimd"

// ShellWatchMetadata is the shape ShellWatch stores under Hydra's per-client
// `metadata` object. Origin is the discriminator the consent page and the
// authorized-clients view read.
type ShellWatchMetadata struct {
	Origin    string `json:"origin"`
	FetchedAt string `json:"fetched_at,omitempty"`
}

// CIMDResolver resolves URL client_ids and keeps the matching Hydra client in
// sync. Safe for concurrent use: work on one client_id is serialized, so N
// simultaneous first-time authorizations provision exactly once.
type CIMDResolver struct {
	admin   Admin
	fetcher *Fetcher
	policy  ClientPolicy
	clk     clock.Clock

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// CIMDResolverParams wires the resolver.
type CIMDResolverParams struct {
	Admin   Admin
	Fetcher *Fetcher
	Policy  ClientPolicy
	Clock   clock.Clock
}

func NewCIMDResolver(p CIMDResolverParams) *CIMDResolver {
	clk := p.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	return &CIMDResolver{
		admin:   p.Admin,
		fetcher: p.Fetcher,
		policy:  p.Policy,
		clk:     clk,
		locks:   map[string]*sync.Mutex{},
	}
}

// Resolution is what the front door needs to carry on with the authorization.
type Resolution struct {
	Doc ClientMetadata
	// FirstSeen is true when this request is what brought the client into
	// existence in Hydra (drives the consent page's "first time seen" hint).
	FirstSeen bool
	// MaterialChange is true when the document changed its authentication
	// shape or its keys (draft §9.2). The resolver cannot act on it — no
	// subject exists before login — so the consent step consumes it.
	MaterialChange bool
}

// Resolve validates the Client Identifier URL, fetches and validates its
// document, checks the request's redirect_uri against it, and provisions or
// refreshes the Hydra client.
//
// requestedRedirectURI and requestedScope come from the authorization request;
// an empty redirect_uri skips the match (Hydra then rejects the request itself,
// and the front door must not redirect to an unvalidated URI).
func (r *CIMDResolver) Resolve(ctx context.Context, clientIDURL, requestedRedirectURI, requestedScope string) (Resolution, error) {
	if _, err := ValidateClientIDURL(clientIDURL); err != nil {
		return Resolution{}, err
	}

	unlock := r.lockFor(clientIDURL)
	defer unlock()

	doc, cached, err := r.fetcher.Fetch(ctx, clientIDURL, r.policy)
	if err != nil {
		return Resolution{}, err
	}
	if requestedRedirectURI != "" && !MatchRedirectURI(doc.RedirectURIs, requestedRedirectURI) {
		return Resolution{}, fmt.Errorf("redirect_uri is not registered in the client metadata document")
	}
	scope, err := GrantedScope(requestedScope, r.policy.AllowedScopes)
	if err != nil {
		return Resolution{}, err
	}

	// A cache hit means we already provisioned this exact document; skip the
	// Hydra round trip entirely.
	if cached {
		return Resolution{Doc: doc}, nil
	}

	firstSeen, material, err := r.provision(ctx, clientIDURL, doc, scope)
	if err != nil {
		// Do not keep a document we could not apply — the next attempt
		// re-reads rather than serving a client Hydra does not have.
		r.fetcher.Invalidate(clientIDURL)
		return Resolution{}, err
	}
	return Resolution{Doc: doc, FirstSeen: firstSeen, MaterialChange: material}, nil
}

// provision creates or updates the Hydra client. It reports whether the client
// was newly created, and whether an existing one changed materially.
func (r *CIMDResolver) provision(ctx context.Context, clientIDURL string, doc ClientMetadata, scope []string) (firstSeen, material bool, err error) {
	desired := r.desiredClient(clientIDURL, doc, scope)

	existing, err := r.admin.GetClient(ctx, clientIDURL)
	if err != nil {
		return false, false, fmt.Errorf("client registration failed")
	}
	if existing == nil {
		if _, err := r.admin.CreateClient(ctx, desired); err == nil {
			return true, false, nil
		} else if apiErr, ok := err.(*APIError); !ok || apiErr.Status != http.StatusConflict {
			return false, false, fmt.Errorf("client registration failed")
		}
		// A concurrent writer won the race (another process, or an operator).
		// Re-read and fall through to the update path.
		existing, err = r.admin.GetClient(ctx, clientIDURL)
		if err != nil || existing == nil {
			return false, false, fmt.Errorf("client registration failed")
		}
	}

	if !isCIMDClient(existing) {
		// Someone else owns this id. Leave it completely alone; the
		// authorization still proceeds against their registration.
		slog.Warn("cimd: refusing to overwrite a client ShellWatch did not create from CIMD",
			"client_id", clientIDURL)
		return false, false, nil
	}
	if !clientChanged(existing, desired) {
		return false, false, nil
	}
	material = materialChange(existing, desired)
	if _, err := r.admin.UpdateClient(ctx, clientIDURL, desired); err != nil {
		return false, false, fmt.Errorf("client registration failed")
	}
	return false, material, nil
}

func (r *CIMDResolver) desiredClient(clientIDURL string, doc ClientMetadata, scope []string) OAuth2Client {
	meta, _ := json.Marshal(map[string]any{
		"shellwatch": ShellWatchMetadata{
			Origin:    OriginCIMD,
			FetchedAt: r.clk.Now().UTC().Format(clock.ISOMillis),
		},
	})
	var metadata map[string]any
	_ = json.Unmarshal(meta, &metadata)

	return OAuth2Client{
		ClientID:                clientIDURL,
		ClientName:              doc.ClientName,
		GrantTypes:              doc.GrantTypes,
		ResponseTypes:           doc.ResponseTypes,
		Scope:                   strings.Join(scope, " "),
		RedirectURIs:            doc.RedirectURIs,
		TokenEndpointAuthMethod: doc.TokenEndpointAuthMethod,
		JwksURI:                 doc.JwksURI,
		Jwks:                    doc.Jwks,
		ClientURI:               doc.ClientURI,
		// logo_uri is deliberately NOT carried over: the consent page renders
		// no remote logo (draft §9.3 — phishing and cross-domain tracking),
		// and prefetching/moderating one is out of scope.
		Metadata: metadata,
	}
}

// lockFor serializes work on one client_id and returns the unlock func.
func (r *CIMDResolver) lockFor(key string) func() {
	r.mu.Lock()
	m, ok := r.locks[key]
	if !ok {
		m = &sync.Mutex{}
		r.locks[key] = m
	}
	r.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// isCIMDClient reports whether ShellWatch provisioned this client from CIMD.
func isCIMDClient(c *OAuth2Client) bool {
	if c == nil {
		return false
	}
	sw, ok := c.Metadata["shellwatch"].(map[string]any)
	if !ok {
		return false
	}
	origin, _ := sw["origin"].(string)
	return origin == OriginCIMD
}

// clientChanged compares the fields CIMD owns, ignoring `metadata` (whose
// fetched_at changes on every refresh and would force a pointless write).
func clientChanged(existing *OAuth2Client, desired OAuth2Client) bool {
	return existing.ClientName != desired.ClientName ||
		existing.Scope != desired.Scope ||
		existing.TokenEndpointAuthMethod != desired.TokenEndpointAuthMethod ||
		existing.JwksURI != desired.JwksURI ||
		existing.ClientURI != desired.ClientURI ||
		!sameStrings(existing.RedirectURIs, desired.RedirectURIs) ||
		!sameStrings(existing.GrantTypes, desired.GrantTypes) ||
		!sameStrings(existing.ResponseTypes, desired.ResponseTypes) ||
		!sameJSON(existing.Jwks, desired.Jwks)
}

// materialChange reports a change that invalidates remembered consent: the
// client's authentication shape or its keys. Changed redirect_uris just
// replace (the user approved the client, not its port).
func materialChange(existing *OAuth2Client, desired OAuth2Client) bool {
	return existing.TokenEndpointAuthMethod != desired.TokenEndpointAuthMethod ||
		existing.JwksURI != desired.JwksURI ||
		!sameJSON(existing.Jwks, desired.Jwks)
}

// sameStrings compares as sets — Hydra may reorder on round-trip.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func sameJSON(a, b map[string]any) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
