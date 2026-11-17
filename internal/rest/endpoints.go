// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package rest holds the account-scoped REST handlers (port of
// src/server/routes/). Validation, error wording, and response envelopes
// match Node exactly (pinned by endpoints-* and err-400-endpoint-* goldens).
// Handlers are hand-mounted on chi and marshal the generated model types
// (internal/api) where the spec models the body, so response shapes are
// compile-checked against the frozen contract; goldens remain the value-level
// oracle.
package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/api"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/realip"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/webauthn"
)

const demoReadOnlyMsg = "Demo endpoints are read-only — toggle visibility instead"

// Endpoints wires the endpoint CRUD routes.
type Endpoints struct {
	Svc *endpointsvc.Service
	// NewID generates endpoint ids (UUID); injected for testability.
	NewID func() string
	// StepUp gates the host-key routes (#241).
	StepUp *webauthn.StepUpStore
}

func (e *Endpoints) Mount(r chi.Router) {
	r.Get("/api/endpoints", e.list)
	r.Post("/api/endpoints", e.create)
	r.Put("/api/endpoints/{id}", e.update)
	r.Delete("/api/endpoints/{id}", e.delete)
	// Host-key management (#241): both are trust decisions → step-up gated.
	r.With(e.StepUp.RequireStepUp(webauthn.ActionPinHostKey)).
		Put("/api/endpoints/{id}/host-key", e.pinHostKey)
	r.With(e.StepUp.RequireStepUp(webauthn.ActionResetHostKey)).
		Delete("/api/endpoints/{id}/host-key", e.deleteHostKey)
}

func toDTO(ep store.Endpoint, isDemo bool) api.Endpoint {
	var hostKey *api.EndpointHostKey
	if ep.HostKey != nil {
		hostKey = &api.EndpointHostKey{
			Type: ep.HostKey.Type, Fingerprint: ep.HostKey.Fingerprint,
			PinnedAt: ep.HostKey.PinnedAt, PinnedBy: ep.HostKey.PinnedBy,
		}
	}
	return api.Endpoint{
		Id: ep.ID, Label: ep.Label, Host: ep.Host, Port: int(ep.Port), Username: ep.Username,
		UserVerification: api.EndpointUserVerification(ep.UserVerification),
		AgentForward:     ep.AgentForward, Description: ep.Description, IsDemo: isDemo,
		HostKey: hostKey,
	}
}

func (e *Endpoints) list(w http.ResponseWriter, r *http.Request) {
	eps, err := e.Svc.ListForAccount(r.Context(), accountID(r))
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	out := make([]api.Endpoint, 0, len(eps))
	for _, ep := range eps {
		out = append(out, toDTO(ep.Endpoint, ep.IsDemo))
	}
	writeJSON(w, 200, map[string]any{"endpoints": out})
}

// patchFromBody decodes an endpoint body as Node did: a non-string string
// field reads as "", a non-integer port is ignored. agentForward must be a
// boolean and description a string or null; the service checks the rest.
func patchFromBody(body map[string]json.RawMessage) (endpointsvc.EndpointPatch, string) {
	var p endpointsvc.EndpointPatch
	str := func(key string) *string {
		raw, ok := body[key]
		if !ok {
			return nil
		}
		v := jsonString(raw)
		return &v
	}
	p.Label, p.Host, p.Username, p.UserVerification = str("label"), str("host"), str("username"), str("userVerification")
	if raw, ok := body["port"]; ok {
		var port *int64
		if json.Unmarshal(raw, &port) == nil {
			p.Port = port
		}
	}
	if raw, ok := body["agentForward"]; ok {
		if !isJSONBool(raw) {
			return p, "agentForward must be a boolean"
		}
		fwd := string(raw) == "true"
		p.AgentForward = &fwd
	}
	if raw, ok := body["description"]; ok {
		p.DescriptionSet = true
		if json.Unmarshal(raw, &p.Description) != nil { // null clears
			return p, "description must be a string up to 1000 characters"
		}
	}
	return p, ""
}

func (e *Endpoints) create(w http.ResponseWriter, r *http.Request) {
	patch, msg := patchFromBody(readRawBody(r))
	if msg != "" {
		writeErr(w, 400, msg)
		return
	}
	id := e.NewID()
	if err := e.Svc.Create(r.Context(), endpointsvc.CreateParams{ID: id, AccountID: accountID(r), Patch: patch}); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, api.StatusCreated{Status: api.Created, Id: id})
}

func (e *Endpoints) update(w http.ResponseWriter, r *http.Request) {
	patch, msg := patchFromBody(readRawBody(r))
	if msg != "" {
		writeErr(w, 400, msg)
		return
	}
	ok, err := e.Svc.Update(r.Context(), endpointsvc.UpdateParams{
		ID: chi.URLParam(r, "id"), AccountID: accountID(r), Patch: patch,
		By: endpointsvc.Actor{Via: "REST", SourceIP: realip.FromRequest(r)},
	})
	switch {
	case errors.Is(err, endpointsvc.ErrDemoReadOnly):
		writeErr(w, 400, demoReadOnlyMsg)
	case err != nil:
		writeErr(w, 400, err.Error())
	case !ok:
		writeErr(w, 400, "Endpoint not found")
	default:
		writeJSON(w, 200, api.StatusUpdated{Status: api.Updated})
	}
}

func (e *Endpoints) delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ok, err := e.Svc.Delete(r.Context(), id, accountID(r))
	switch {
	case errors.Is(err, endpointsvc.ErrDemoReadOnly):
		writeErr(w, 400, demoReadOnlyMsg)
		return
	case errors.Is(err, endpointsvc.ErrActiveSessions):
		writeErr(w, 409, err.Error())
		return
	case err != nil:
		writeErr(w, 400, err.Error())
		return
	case !ok:
		writeErr(w, 404, "Endpoint not found")
		return
	}
	writeJSON(w, 200, api.StatusDeleted{Status: api.Deleted})
}

// pinHostKey manually pins an endpoint's host key before first connection
// (#241; step-up gated). Body: exactly one of publicKey (OpenSSH line,
// preferred) or fingerprint ("SHA256:..."). Compare-and-set: an existing pin
// is never overwritten — "replace" = delete + pin.
func (e *Endpoints) pinHostKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if demo.IsID(id) {
		writeErr(w, 400, demoReadOnlyMsg)
		return
	}
	body := readRawBody(r)
	publicKey := strings.TrimSpace(stringField(body, "publicKey"))
	fingerprint := strings.TrimSpace(stringField(body, "fingerprint"))
	if (publicKey == "") == (fingerprint == "") {
		writeErr(w, 400, "Provide exactly one of publicKey (OpenSSH public-key line) or fingerprint (SHA256:...)")
		return
	}
	var rec store.HostKeyRecord
	if publicKey != "" {
		hk, err := config.ParseHostKey(publicKey)
		if err != nil || hk.Key == nil {
			writeErr(w, 400, "publicKey must be an OpenSSH public-key line (e.g. \"ssh-ed25519 AAAA...\")")
			return
		}
		rec = store.HostKeyRecord{Type: hk.Type, Key: hk.Key, Fingerprint: hk.Fingerprint}
	} else {
		if !strings.HasPrefix(fingerprint, "SHA256:") {
			writeErr(w, 400, "fingerprint must start with SHA256:")
			return
		}
		rec = store.HostKeyRecord{Fingerprint: fingerprint}
	}
	existing, err := e.Svc.Endpoints.GetForAccount(r.Context(), id, accountID(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if existing == nil {
		writeErr(w, 400, "Endpoint not found")
		return
	}
	// Bind the write to the address just read: a concurrent host/port update
	// fails the CAS instead of landing the key on the new address.
	if err := e.Svc.Endpoints.PinHostKey(r.Context(), store.PinHostKeyParams{
		ID: id, Host: existing.Host, Port: existing.Port, Record: rec, PinnedBy: "manual",
	}); err != nil {
		if errors.Is(err, store.ErrHostKeyPinned) {
			writeErr(w, 409, "A host key is already pinned for this endpoint — delete it first")
			return
		}
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, api.StatusUpdated{Status: api.Updated})
}

// deleteHostKey forgets an endpoint's pinned host key (#241; step-up gated).
// The recovery path after a mismatch; idempotent on an absent pin.
func (e *Endpoints) deleteHostKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if demo.IsID(id) {
		writeErr(w, 400, demoReadOnlyMsg)
		return
	}
	existing, err := e.Svc.Endpoints.GetForAccount(r.Context(), id, accountID(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if existing == nil {
		writeErr(w, 400, "Endpoint not found")
		return
	}
	cleared, err := e.Svc.Endpoints.ClearHostKey(r.Context(), id, accountID(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if cleared && existing.HostKey != nil {
		e.Svc.AuditHostKeyCleared(*existing, "host key forgotten via settings", endpointsvc.Actor{Via: "REST"})
	}
	writeJSON(w, 200, api.StatusDeleted{Status: api.Deleted})
}
