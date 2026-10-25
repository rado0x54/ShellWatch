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
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/api"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/store"
)

// SessionLister reports the endpoint ids an account currently has open
// sessions against (satisfied by terminal.Manager; nil until Phase 3 slice 2
// wires it, so delete skips the active-session guard).
type SessionLister interface {
	EndpointIDsForAccount(accountID string) []string
}

// Endpoints wires the endpoint CRUD routes.
type Endpoints struct {
	Svc      *endpointsvc.Service
	Sessions SessionLister
	// NewID generates endpoint ids (UUID); injected for testability.
	NewID func() string
}

func (e *Endpoints) Mount(r chi.Router) {
	r.Get("/api/endpoints", e.list)
	r.Post("/api/endpoints", e.create)
	r.Put("/api/endpoints/{id}", e.update)
	r.Delete("/api/endpoints/{id}", e.delete)
}

func toDTO(ep store.Endpoint, isDemo bool) api.Endpoint {
	return api.Endpoint{
		Id: ep.ID, Label: ep.Label, Host: ep.Host, Port: int(ep.Port), Username: ep.Username,
		UserVerification: api.EndpointUserVerification(ep.UserVerification),
		AgentForward:     ep.AgentForward, Description: ep.Description, IsDemo: isDemo,
	}
}

func (e *Endpoints) list(w http.ResponseWriter, r *http.Request) {
	eps, err := e.Svc.ListForAccount(r.Context(), accountID(r))
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	out := make([]api.Endpoint, 0, len(eps))
	for _, ep := range eps {
		out = append(out, toDTO(ep.Endpoint, ep.IsDemo))
	}
	writeJSON(w, 200, map[string]any{"endpoints": out})
}

func (e *Endpoints) create(w http.ResponseWriter, r *http.Request) {
	body := readRawBody(r)

	label := strings.TrimSpace(stringField(body, "label"))
	host := strings.TrimSpace(stringField(body, "host"))
	if label == "" || host == "" {
		writeErr(w, 400, "label and host are required")
		return
	}
	uv := "required"
	if raw, ok := body["userVerification"]; ok {
		v := jsonString(raw)
		if !endpointsvc.IsUserVerification(v) {
			writeErr(w, 400, userVerificationErr())
			return
		}
		uv = v
	}
	if raw, ok := body["agentForward"]; ok && !isJSONBool(raw) {
		writeErr(w, 400, "agentForward must be a boolean")
		return
	}
	desc, ok := normalizeDescription(body["description"])
	if !ok {
		writeErr(w, 400, descriptionErr())
		return
	}

	port := int64(22)
	if raw, ok := body["port"]; ok {
		_ = json.Unmarshal(raw, &port)
	}
	username := "shellwatch"
	if raw, ok := body["username"]; ok {
		username = jsonString(raw)
	}
	agentForward := true
	if raw, ok := body["agentForward"]; ok {
		_ = json.Unmarshal(raw, &agentForward)
	}

	id := e.NewID()
	if err := e.Svc.Endpoints.Create(r.Context(), store.Endpoint{
		ID: id, AccountID: accountID(r), Label: label, Host: host, Port: port,
		Username: username, UserVerification: uv, Description: desc, AgentForward: agentForward,
	}); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, api.StatusCreated{Status: api.Created, Id: id})
}

func (e *Endpoints) update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if demo.IsID(id) {
		writeErr(w, 400, "Demo endpoints are read-only — toggle visibility instead")
		return
	}
	body := readRawBody(r)
	if raw, ok := body["userVerification"]; ok && !endpointsvc.IsUserVerification(jsonString(raw)) {
		writeErr(w, 400, userVerificationErr())
		return
	}
	if raw, ok := body["agentForward"]; ok && !isJSONBool(raw) {
		writeErr(w, 400, "agentForward must be a boolean")
		return
	}
	descSet := false
	var desc *string
	if raw, present := body["description"]; present {
		d, ok := normalizeDescription(raw)
		if !ok {
			writeErr(w, 400, descriptionErr())
			return
		}
		desc, descSet = d, true
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
	merged := *existing
	if raw, ok := body["label"]; ok {
		merged.Label = jsonString(raw)
	}
	if raw, ok := body["host"]; ok {
		merged.Host = jsonString(raw)
	}
	if raw, ok := body["port"]; ok {
		_ = json.Unmarshal(raw, &merged.Port)
	}
	if raw, ok := body["username"]; ok {
		merged.Username = jsonString(raw)
	}
	if raw, ok := body["userVerification"]; ok {
		merged.UserVerification = jsonString(raw)
	}
	if raw, ok := body["agentForward"]; ok {
		_ = json.Unmarshal(raw, &merged.AgentForward)
	}
	if descSet {
		merged.Description = desc
	}
	if _, err := e.Svc.Endpoints.Update(r.Context(), merged); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, api.StatusUpdated{Status: api.Updated})
}

func (e *Endpoints) delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if demo.IsID(id) {
		writeErr(w, 400, "Demo endpoints are read-only — toggle visibility instead")
		return
	}
	if e.Sessions != nil {
		for _, epID := range e.Sessions.EndpointIDsForAccount(accountID(r)) {
			if epID == id {
				writeErr(w, 409, "Cannot delete endpoint with active sessions")
				return
			}
		}
	}
	if _, err := e.Svc.Endpoints.Delete(r.Context(), id, accountID(r)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, api.StatusDeleted{Status: api.Deleted})
}

// normalizeDescription mirrors normalizeDescription in endpoints.ts: tri-state
// JSON (absent/null -> nil, string -> trimmed or nil, too long/non-string -> !ok).
func normalizeDescription(raw json.RawMessage) (*string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false
	}
	if len(s) > endpointsvc.DescriptionMaxLen {
		return nil, false
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, true
	}
	return &trimmed, true
}

func userVerificationErr() string {
	return "userVerification must be one of: " + strings.Join(endpointsvc.UserVerificationValues, ", ")
}

func descriptionErr() string {
	return "description must be a string up to 1000 characters"
}
