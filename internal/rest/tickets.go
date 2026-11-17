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
	"strings"
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
	// ExternalURL yields server.externalUrl. The share link is built from it:
	// the guest routes accept only that origin, so a link built from the
	// owner's own address (a LAN IP, an alternate name, the dev server's
	// port) would be refused.
	ExternalURL func() string
}

func (t *Tickets) Mount(r chi.Router) {
	r.Post("/api/endpoints/{id}/tickets", t.mint)
	r.Get("/api/tickets", t.list)
	r.Delete("/api/tickets/{id}", t.revoke)
}

func (t *Tickets) mint(w http.ResponseWriter, r *http.Request) {
	acc := accountID(r)
	endpointID, err := pathParam(r, "id")
	if err != nil {
		writeErr(w, 400, "invalid id encoding")
		return
	}
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
		// Clamp before converting: a huge value would overflow the
		// Duration and could wrap into the allowed range. Anything this
		// large fails the bounds check in ValidateOptions anyway.
		const maxSeconds = 1e9
		if n > maxSeconds {
			n = maxSeconds
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
		AccountID: acc, EndpointID: endpointID, Options: opts,
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
	writeJSON(w, 201, map[string]any{
		"ticket": minted.Ticket, "token": minted.Token, "shareLink": t.shareLink(minted.Token),
	})
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
	id, err := pathParam(r, "id")
	if err != nil {
		writeErr(w, 400, "invalid id encoding")
		return
	}
	switch err := t.Service.Revoke(accountID(r), id); {
	case errors.Is(err, ticket.ErrAlreadyEnded):
		writeErr(w, 409, "Ticket already ended")
		return
	case err != nil:
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

// guestPreamble is shared by the two guest REST routes: no caching, and the
// Origin must be the configured external origin (login CSRF: a foreign page
// must not plant a guest cookie, nor probe tickets from a victim's browser).
// False when it answered 403.
func (t *TicketRedeem) guestPreamble(w http.ResponseWriter, r *http.Request, op, ip string) bool {
	w.Header().Set("Cache-Control", "no-store")
	origin := r.Header.Get("Origin")
	if !auth.OriginAllowed(t.ExternalURL(), origin) {
		slog.Warn("ticket: "+op+" rejected", "reason", "origin not allowed", "sourceIp", ip,
			"origin", auth.OriginHost(origin), "expected", auth.OriginHost(t.ExternalURL()))
		apierr.Write(w, http.StatusForbidden, "Forbidden")
		return false
	}
	return true
}

// Check answers whether a ticket can still be redeemed, without consuming
// it, so the guest page shows an invalid link at once (and asks for a reason
// only when the ticket requires one). Same uniform 404 as redeem; no cookie,
// no principal.
func (t *TicketRedeem) Check(w http.ResponseWriter, r *http.Request) {
	ip := realip.FromRequest(r)
	if !t.guestPreamble(w, r, "check", ip) {
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, redeemBodyMax)).Decode(&body)
	res, err := t.Service.Check(r.Context(), body.Token, ip)
	switch {
	case errors.Is(err, ticket.ErrUnavailable):
		apierr.Write(w, http.StatusServiceUnavailable, "Temporarily unavailable; try again")
		return
	case err != nil:
		apierr.Write(w, http.StatusNotFound, "Not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reasonRequired": res.ReasonRequired})
}

// ServeHTTP handles a redemption. It never calls auth.PrincipalFrom.
func (t *TicketRedeem) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := realip.FromRequest(r)
	if !t.guestPreamble(w, r, "redeem", ip) {
		return
	}
	var cookie string
	if ck, err := r.Cookie(ticket.CookieName); err == nil {
		cookie = ck.Value
	}
	var body struct {
		Token  string `json:"token"`
		Reason string `json:"reason"`
		// ReplaceCurrent: end this browser's current guest session instead
		// of answering 409.
		ReplaceCurrent bool `json:"replaceCurrent"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, redeemBodyMax)).Decode(&body)
	res, err := t.Service.Redeem(r.Context(), ticket.RedeemParams{
		Token: body.Token, Reason: body.Reason, SourceIP: ip, UserAgent: r.UserAgent(),
		Cookie: cookie, Channel: terminal.TicketChannelWeb, ReplaceCurrent: body.ReplaceCurrent,
	})
	var capErr *ticket.CapacityError
	switch {
	case errors.Is(err, ticket.ErrLiveGuest):
		apierr.Write(w, http.StatusConflict, "A guest session is already active in this browser")
		return
	case errors.Is(err, ticket.ErrReasonRequired):
		apierr.Write(w, http.StatusBadRequest, "A reason is required")
		return
	case errors.Is(err, ticket.ErrUnavailable):
		// The ticket is untouched; the guest page offers to try again.
		apierr.Write(w, http.StatusServiceUnavailable, "Temporarily unavailable; try again")
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

// shareLink is the guest's link: externalUrl's origin, /t, and the token in
// the fragment (which never reaches a server log or a Referer).
func (t *Tickets) shareLink(token string) string {
	base := ""
	if t.ExternalURL != nil {
		base = strings.TrimRight(t.ExternalURL(), "/")
	}
	return base + "/t#" + token
}
