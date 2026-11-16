// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// One-time access tickets (#306). The owner routes (mint, list, revoke) sit
// behind the bearer gate like every other /api route. Redeem is the guest's
// route: gate-exempt, its only credential is the ticket in the body, and it
// must never read a principal — a bearer that is present, valid, invalid or
// for another account changes nothing.
package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/apierr"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/realip"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/ticket"
)

// Tickets wires the owner's ticket routes.
type Tickets struct {
	Service *ticket.Service
}

func (t *Tickets) Mount(r chi.Router) {
	r.Post("/api/endpoints/{id}/tickets", t.mint)
	r.Get("/api/tickets", t.list)
	r.Delete("/api/tickets/{id}", t.revoke)
}

func (t *Tickets) mint(w http.ResponseWriter, r *http.Request) {
	acc := accountID(r)
	body := readRawBody(r)
	opts := ticket.Options{ReasonRequired: true}
	if raw, ok := body["label"]; ok && string(raw) != "null" {
		var v string
		if json.Unmarshal(raw, &v) != nil {
			writeErr(w, 400, "label must be a string")
			return
		}
		opts.Label = v
	}
	for _, f := range []struct {
		key string
		dst *time.Duration
	}{{"redeemTtlSeconds", &opts.RedeemTTL}, {"lifetimeSeconds", &opts.Lifetime}} {
		raw, ok := body[f.key]
		if !ok || string(raw) == "null" {
			continue
		}
		var n float64
		if json.Unmarshal(raw, &n) != nil || n != float64(int64(n)) {
			writeErr(w, 400, f.key+" must be an integer")
			return
		}
		if n <= 0 {
			writeErr(w, 400, f.key+" must be positive")
			return
		}
		*f.dst = time.Duration(n) * time.Second
	}
	for _, f := range []struct {
		key string
		dst *bool
	}{{"reasonRequired", &opts.ReasonRequired}, {"agentForward", &opts.AgentForward}} {
		raw, ok := body[f.key]
		if !ok || string(raw) == "null" {
			continue
		}
		if !isJSONBool(raw) {
			writeErr(w, 400, f.key+" must be a boolean")
			return
		}
		*f.dst = string(raw) == "true"
	}
	minted, err := t.Service.Mint(r.Context(), ticket.MintParams{
		AccountID: acc, EndpointID: chi.URLParam(r, "id"), Options: opts,
	})
	var optErr *ticket.OptionError
	switch {
	case errors.As(err, &optErr):
		writeErr(w, 400, optErr.Msg)
		return
	case errors.Is(err, ticket.ErrEndpointNotFound):
		writeErr(w, 404, "Endpoint not found")
		return
	case errors.Is(err, ticket.ErrTooManyTickets):
		writeErr(w, 409, "Too many outstanding tickets ("+strconv.Itoa(ticket.MaxOutstanding)+")")
		return
	case err != nil:
		writeInternal(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, map[string]any{"ticket": minted.Ticket, "token": minted.Token})
}

func (t *Tickets) list(w http.ResponseWriter, r *http.Request) {
	views := t.Service.List(accountID(r))
	if ep := r.URL.Query().Get("endpointId"); ep != "" {
		kept := views[:0]
		for _, v := range views {
			if v.EndpointID == ep {
				kept = append(kept, v)
			}
		}
		views = kept
	}
	writeJSON(w, 200, map[string]any{"tickets": views})
}

func (t *Tickets) revoke(w http.ResponseWriter, r *http.Request) {
	if !t.Service.Revoke(accountID(r), chi.URLParam(r, "id")) {
		writeErr(w, 404, "Ticket not found")
		return
	}
	writeJSON(w, 200, map[string]any{"status": "revoked"})
}

// TicketRedeem is the guest's redeem route (POST /api/tickets/redeem).
type TicketRedeem struct {
	Service *ticket.Service
	// ExternalURL yields server.externalUrl, the only accepted Origin.
	ExternalURL func() string
}

// redeemBodyMax bounds the redeem body (a token and a short reason).
const redeemBodyMax = 8 << 10

// ServeHTTP handles a redemption. It never calls auth.PrincipalFrom.
func (t *TicketRedeem) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ip := realip.FromRequest(r)
	origin := r.Header.Get("Origin")
	if !auth.OriginAllowed(t.ExternalURL(), origin) {
		// Login CSRF: a foreign page must not plant a guest cookie.
		slog.Warn("ws: guest origin rejected", "route", "redeem", "sourceIp", ip,
			"origin", auth.OriginHost(origin), "expected", auth.OriginHost(t.ExternalURL()))
		apierr.Write(w, http.StatusForbidden, "Forbidden")
		return
	}
	var cookie string
	if ck, err := r.Cookie(ticket.CookieName); err == nil {
		cookie = ck.Value
	}
	var body struct {
		Token  string `json:"token"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, redeemBodyMax)).Decode(&body)
	res, err := t.Service.Redeem(r.Context(), ticket.RedeemParams{
		Token: body.Token, Reason: body.Reason, SourceIP: ip, UserAgent: r.UserAgent(),
		Cookie: cookie, Channel: terminal.TicketChannelWeb,
	})
	var capErr *ticket.CapacityError
	switch {
	case errors.Is(err, ticket.ErrLiveGuest):
		apierr.Write(w, http.StatusConflict, "A guest session is already active in this browser")
		return
	case errors.Is(err, ticket.ErrReasonRequired):
		apierr.Write(w, http.StatusBadRequest, "A reason is required")
		return
	case errors.As(err, &capErr):
		w.Header().Set("Retry-After", strconv.Itoa(int(capErr.RetryAfter.Round(time.Second)/time.Second)))
		apierr.Write(w, http.StatusTooManyRequests, "Too many guest sessions right now; try again later")
		return
	case err != nil:
		// Unknown, used, expired, revoked or ineligible: one uniform answer.
		apierr.Write(w, http.StatusNotFound, "Not found")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: ticket.CookieName, Value: res.Cookie, Path: "/",
		MaxAge: int(res.CookieMaxAge / time.Second), Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"confirmationCode":       res.ConfirmationCode,
		"attachDeadline":         res.AttachDeadline.UTC().Format(clock.ISOMillis),
		"admissionWindowSeconds": int(res.AdmissionWindow / time.Second),
		"lifetimeSeconds":        int(res.Lifetime / time.Second),
		"agentForward":           res.AgentForward,
	})
}
