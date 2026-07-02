// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package rest holds the account-scoped REST handlers (port of
// src/server/routes/). Slice 1 is endpoints CRUD; sessions/keys follow.
// Validation, error wording, and response envelopes match Node exactly
// (pinned by endpoints-* and err-400-endpoint-* goldens). Handlers are
// hand-mounted on chi; the generated api.StrictServerInterface is adopted as
// a later refactor once every surface exists (a converge-later item, like the
// A-J inconsistencies).
package rest

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/store"
)

const endpointDescriptionMaxLen = 1000

var userVerificationValues = []string{"required", "preferred", "discouraged"}

func isUserVerification(v string) bool {
	for _, u := range userVerificationValues {
		if u == v {
			return true
		}
	}
	return false
}

// SessionLister reports the endpoint ids an account currently has open
// sessions against (satisfied by terminal.Manager; nil until Phase 3 slice 2
// wires it, so delete skips the active-session guard).
type SessionLister interface {
	EndpointIDsForAccount(accountID string) []string
}

// Endpoints wires the endpoint CRUD routes.
type Endpoints struct {
	Store    *store.Endpoints
	Demo     *demo.Service
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

type endpointDTO struct {
	ID               string  `json:"id"`
	Label            string  `json:"label"`
	Host             string  `json:"host"`
	Port             int64   `json:"port"`
	Username         string  `json:"username"`
	UserVerification string  `json:"userVerification"`
	AgentForward     bool    `json:"agentForward"`
	Description      *string `json:"description"`
	IsDemo           bool    `json:"isDemo"`
}

func toDTO(ep store.Endpoint, isDemo bool) endpointDTO {
	return endpointDTO{
		ID: ep.ID, Label: ep.Label, Host: ep.Host, Port: ep.Port, Username: ep.Username,
		UserVerification: ep.UserVerification, AgentForward: ep.AgentForward,
		Description: ep.Description, IsDemo: isDemo,
	}
}

func (e *Endpoints) list(w http.ResponseWriter, r *http.Request) {
	acc := accountID(r)
	own, err := e.Store.ListForAccount(r.Context(), acc)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	out := make([]endpointDTO, 0, len(own))
	for _, ep := range own {
		out = append(out, toDTO(ep, false))
	}
	if show, _ := e.Store.ShowDemoEndpoints(r.Context(), acc); show && e.Demo != nil {
		for _, ep := range e.Demo.List(acc) {
			out = append(out, toDTO(ep, true))
		}
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
		if !isUserVerification(v) {
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
	if err := e.Store.Create(r.Context(), store.Endpoint{
		ID: id, AccountID: accountID(r), Label: label, Host: host, Port: port,
		Username: username, UserVerification: uv, Description: desc, AgentForward: agentForward,
	}); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"status": "created", "id": id})
}

func (e *Endpoints) update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if demo.IsID(id) {
		writeErr(w, 400, "Demo endpoints are read-only — toggle visibility instead")
		return
	}
	body := readRawBody(r)
	if raw, ok := body["userVerification"]; ok && !isUserVerification(jsonString(raw)) {
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

	existing, err := e.Store.GetForAccount(r.Context(), id, accountID(r))
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
	if _, err := e.Store.Update(r.Context(), merged); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"status": "updated"})
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
	if _, err := e.Store.Delete(r.Context(), id, accountID(r)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"status": "deleted"})
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
	if len(s) > endpointDescriptionMaxLen {
		return nil, false
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, true
	}
	return &trimmed, true
}

func userVerificationErr() string {
	return "userVerification must be one of: " + strings.Join(userVerificationValues, ", ")
}

func descriptionErr() string {
	return "description must be a string up to 1000 characters"
}
