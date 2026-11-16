// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package ticket owns one-time access tickets and their guest sessions
// (#306). A logged-in owner mints a ticket for one endpoint; an untrusted
// browser redeems it (reason first), attaches the guest WebSocket, and waits
// while the normal endpoint-auth approval decides admission on the owner's
// trusted device. Every transition, limit and deadline of a ticket and its
// guest session goes through this service — handlers and the terminal
// Manager make no lifecycle decisions of their own — and every ending runs
// the one close path (closeLocked).
//
// Tickets and guest sessions are process memory (like transfer-link tokens,
// #263): the token and the guest cookie are kept only as SHA-256 hashes, and
// a restart invalidates both. The audit table records every event.
package ticket

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/util"
)

// Server constants (not ticket options).
const (
	// AttachWindow bounds redeemed -> first guest WebSocket attach.
	AttachWindow = 30 * time.Second
	// AdmissionWindow bounds first attach -> admitted, across all attempts.
	AdmissionWindow = 5 * time.Minute
	// ReconnectGrace is how long a guest session survives with no guest
	// connection attached.
	ReconnectGrace = 60 * time.Second
	// MaxGuestSessions caps an account's live guest sessions (redeemed,
	// pending, refused and open). Separate from max_sessions.
	MaxGuestSessions = 3
	// MaxOutstanding caps an account's unredeemed tickets.
	MaxOutstanding = 20
	// MaxConnections caps guest WebSocket connections per guest session.
	MaxConnections = 8
	// ReasonMaxLen caps the guest's reason (characters, after sanitizing).
	ReasonMaxLen = 200
	// LabelMaxLen caps a ticket label (characters).
	LabelMaxLen = 100
	// UserAgentMaxLen caps the recorded user agent (characters).
	UserAgentMaxLen = 256
)

// Option bounds and defaults (the mint screen's table).
const (
	DefaultRedeemTTL = 5 * time.Minute
	MinRedeemTTL     = time.Minute
	MaxRedeemTTL     = 24 * time.Hour
	DefaultLifetime  = 15 * time.Minute
	MinLifetime      = time.Minute
	MaxLifetime      = 8 * time.Hour
)

// CookieName is the guest credential's cookie. The __Host- prefix forces
// Secure, Path=/ and no Domain, so a sibling subdomain cannot set or
// overwrite it (cookie tossing).
const CookieName = "__Host-sw_guest"

// codeAlphabet has no look-alikes (no 0/O, 1/I).
const codeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

// Generic messages: the only failure texts a guest ever sees.
const (
	MsgNotGranted = "Access was not granted."
	MsgEnded      = "The session has ended."
)

var (
	// ErrNotFound is the uniform redeem failure: unknown, used, expired,
	// revoked or no-longer-eligible tickets are indistinguishable.
	ErrNotFound = errors.New("not found")
	// ErrLiveGuest: this browser already holds a live guest session.
	ErrLiveGuest = errors.New("a guest session is already active in this browser")
	// ErrReasonRequired: the ticket requires a reason and none was given.
	ErrReasonRequired = errors.New("a reason is required")
	// ErrCapacity: the account is at its guest-session cap; the ticket is
	// NOT consumed.
	ErrCapacity = errors.New("too many guest sessions")
	// ErrTooManyTickets: the account has MaxOutstanding unredeemed tickets.
	ErrTooManyTickets = errors.New("too many outstanding tickets")
	// ErrEndpointNotFound: mint for an endpoint the account cannot use.
	ErrEndpointNotFound = errors.New("endpoint not found")
	// ErrGone: the guest session no longer exists.
	ErrGone = errors.New("guest session not found")
	// ErrTooManyConnections: the guest session is at MaxConnections.
	ErrTooManyConnections = errors.New("too many guest connections")
	// ErrUnavailable: redemption could not check eligibility (a cancelled
	// request, a database error). The ticket is left untouched, so the
	// guest can simply try again.
	ErrUnavailable = errors.New("temporarily unavailable")
)

// OptionError is a mint option outside its bounds.
type OptionError struct{ Msg string }

func (e *OptionError) Error() string { return e.Msg }

// Guest states (wire values).
const (
	StateMinted   = "minted"
	StateRedeemed = "redeemed"
	StatePending  = "pending"
	StateRefused  = "refused"
	StateOpen     = "open"
	StateClosed   = "closed"
)

// Status is what a guest connection is told (the guest WS `status` frame).
// It never carries endpoint label, address, user or a server error text.
type Status struct {
	State string `json:"state"`
	// Code is the confirmation code (pending, refused).
	Code string `json:"code,omitempty"`
	// AdmissionDeadline (pending, refused) and RemainingSeconds (refused):
	// how long the guest may still ask.
	AdmissionDeadline string `json:"admissionDeadline,omitempty"`
	RemainingSeconds  *int   `json:"remainingSeconds,omitempty"`
	// LifetimeDeadline (open): the hard end of the session.
	LifetimeDeadline string `json:"lifetimeDeadline,omitempty"`
	// Message is a fixed generic text (refused, closed).
	Message string `json:"message,omitempty"`
	// ServerTime is the server's clock when the frame was built. The guest
	// device's clock may be wrong, so the page counts the deadlines down
	// against this, not against its own time.
	ServerTime string `json:"serverTime"`
}

// Publisher delivers guest frames to the guest's WebSocket connections
// (implemented by the ws guest hub). It is called with the service lock
// held, so it must not call back into the service.
type Publisher interface {
	// GuestStatus sends a status frame to every connection of the guest.
	GuestStatus(guestID string, st Status)
	// GuestOpen binds the guest's connections to its admitted terminal
	// session (with output catch-up); idempotent per connection.
	GuestOpen(guestID, sessionID string)
	// GuestClose sends the final status frame and closes every connection.
	GuestClose(guestID string, st Status)
}

// OwnerNotifier tells the owner's browsers that tickets or session-list
// state changed (implemented by the account ws hub). Called without the
// service lock.
type OwnerNotifier interface {
	TicketsChanged(accountID string)
	SessionsChanged(accountID string)
}

// Auditor records ticket events (satisfied by *audit.TicketEvents).
type Auditor interface {
	Record(ev audit.TicketEvent)
}

// Sessions is the subset of the terminal Manager the service drives.
type Sessions interface {
	Create(ctx context.Context, ep terminal.EndpointRef, expectedAccountID string, trigger terminal.Trigger) (*terminal.Session, error)
	Close(sessionID string, reason terminal.CloseReason)
	SubscribeStatus(fn func(terminal.StatusEvent)) func()
}

// Params configure the service.
type Params struct {
	// Ctx is the server's lifetime; attempts derive from it (never from a
	// request context). Close cancels the derived context.
	Ctx      context.Context
	Manager  Sessions
	Clock    clock.Clock
	Audit    Auditor
	Notifier OwnerNotifier
	// ResolveEndpoint resolves an endpoint for an account (nil when it does
	// not resolve: unknown, foreign, deleted or disabled).
	ResolveEndpoint func(ctx context.Context, endpointID, accountID string) (*terminal.EndpointRef, error)
	// AccountActive reports whether the account exists and is enabled. An
	// error means "could not tell" and never invalidates a ticket.
	AccountActive func(ctx context.Context, accountID string) (bool, error)
	// NewID mints ticket ids.
	NewID func() string
}

// Options are a ticket's per-ticket settings.
type Options struct {
	Label          string
	RedeemTTL      time.Duration
	Lifetime       time.Duration
	ReasonRequired bool
	AgentForward   bool
}

type ticket struct {
	id         string
	accountID  string
	endpointID string
	tokenHash  [32]byte
	opts       Options
	createdAt  time.Time
	expiresAt  time.Time
	guest      *guest
}

type guest struct {
	id         string
	t          *ticket
	cookieHash [32]byte
	code       string
	reason     string
	sourceIP   string
	userAgent  string
	channel    terminal.TicketChannel
	state      string

	redeemedAt        time.Time
	attachDeadline    time.Time
	admissionDeadline time.Time // zero until the first attach
	openedAt          time.Time
	lifetimeDeadline  time.Time

	conns         int
	graceDeadline time.Time // zero while attached (or before the first attach)

	attempt        int
	attemptSession string
	attemptCancel  context.CancelFunc
	sessionID      string // the admitted terminal session
}

// Service is the ticket lifecycle owner.
type Service struct {
	p      Params
	clk    clock.Clock
	ctx    context.Context
	cancel context.CancelFunc
	unsub  func()

	mu        sync.Mutex
	pub       Publisher
	tickets   map[string]*ticket
	byToken   map[[32]byte]*ticket
	guests    map[string]*guest
	byCookie  map[[32]byte]*guest
	bySession map[string]*guest
	closed    bool
}

// New builds the service and subscribes to the Manager's status hook.
func New(p Params) *Service {
	clk := p.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	base := p.Ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	s := &Service{
		p: p, clk: clk, ctx: ctx, cancel: cancel,
		tickets: map[string]*ticket{}, byToken: map[[32]byte]*ticket{},
		guests: map[string]*guest{}, byCookie: map[[32]byte]*guest{}, bySession: map[string]*guest{},
	}
	if p.Manager != nil {
		s.unsub = p.Manager.SubscribeStatus(s.onStatus)
	}
	return s
}

// SetPublisher wires the guest WS hub (set once at the composition root,
// before guest connections are served).
func (s *Service) SetPublisher(pub Publisher) {
	s.mu.Lock()
	s.pub = pub
	s.mu.Unlock()
}

// --- effects run after the lock is released ---------------------------

type closeReq struct {
	sessionID string
	reason    terminal.CloseReason
}

type effects struct {
	audits   []audit.TicketEvent
	closes   []closeReq
	cancels  []context.CancelFunc
	tickets  map[string]bool // accounts whose ticket list changed
	sessions map[string]bool // accounts whose session list changed
}

func (fx *effects) ownerTickets(accountID string) {
	if fx.tickets == nil {
		fx.tickets = map[string]bool{}
	}
	fx.tickets[accountID] = true
}

func (fx *effects) ownerSessions(accountID string) {
	if fx.sessions == nil {
		fx.sessions = map[string]bool{}
	}
	fx.sessions[accountID] = true
}

// apply runs the deferred effects. async closes terminal sessions on their
// own goroutines — required inside a Manager status hook, where a
// synchronous Close would join a pump that has not started yet.
func (s *Service) apply(fx *effects, async bool) {
	for _, c := range fx.cancels {
		c()
	}
	for _, c := range fx.closes {
		if async {
			go s.p.Manager.Close(c.sessionID, c.reason)
		} else {
			s.p.Manager.Close(c.sessionID, c.reason)
		}
	}
	if s.p.Audit != nil {
		for _, ev := range fx.audits {
			s.p.Audit.Record(ev)
		}
	}
	if s.p.Notifier != nil {
		for acc := range fx.tickets {
			s.p.Notifier.TicketsChanged(acc)
		}
		for acc := range fx.sessions {
			s.p.Notifier.SessionsChanged(acc)
		}
	}
}

func (s *Service) event(t *ticket, g *guest, name string) audit.TicketEvent {
	ev := audit.TicketEvent{
		AccountID: t.accountID, TicketID: t.id, Event: name, EndpointID: t.endpointID,
		TicketLabel: t.opts.Label, RedeemTTLSeconds: int(t.opts.RedeemTTL / time.Second),
		LifetimeSeconds: int(t.opts.Lifetime / time.Second),
		ReasonRequired:  t.opts.ReasonRequired, AgentForward: t.opts.AgentForward,
	}
	if g != nil {
		ev.Channel = string(g.channel)
		ev.Reason, ev.SourceIP, ev.UserAgent, ev.ConfirmationCode = g.reason, g.sourceIP, g.userAgent, g.code
		ev.Attempt = g.attempt
		ev.SessionID = g.attemptSession
	}
	return ev
}

// --- mint / list / revoke (owner) ---------------------------------------

// MintParams describe a new ticket.
type MintParams struct {
	AccountID  string
	EndpointID string
	Options    Options
}

// Minted is a new ticket plus its secret token (returned exactly once).
type Minted struct {
	Ticket View
	Token  string
}

// ValidateOptions checks the option bounds; zero durations take defaults.
func ValidateOptions(o Options) (Options, error) {
	o.Label = util.SanitizeFreeText(o.Label, LabelMaxLen)
	if o.RedeemTTL == 0 {
		o.RedeemTTL = DefaultRedeemTTL
	}
	if o.Lifetime == 0 {
		o.Lifetime = DefaultLifetime
	}
	if o.RedeemTTL < MinRedeemTTL || o.RedeemTTL > MaxRedeemTTL {
		return o, &OptionError{"redeemTtlSeconds must be between 60 and 86400"}
	}
	if o.Lifetime < MinLifetime || o.Lifetime > MaxLifetime {
		return o, &OptionError{"lifetimeSeconds must be between 60 and 28800"}
	}
	return o, nil
}

// Mint creates a ticket for one of the account's endpoints.
func (s *Service) Mint(ctx context.Context, p MintParams) (Minted, error) {
	opts, err := ValidateOptions(p.Options)
	if err != nil {
		return Minted{}, err
	}
	ref, err := s.p.ResolveEndpoint(ctx, p.EndpointID, p.AccountID)
	if err != nil {
		return Minted{}, err
	}
	if ref == nil {
		return Minted{}, ErrEndpointNotFound
	}
	token := randomToken()
	now := s.clk.Now()
	t := &ticket{
		id: s.p.NewID(), accountID: p.AccountID, endpointID: ref.ID, tokenHash: hash(token),
		opts: opts, createdAt: now, expiresAt: now.Add(opts.RedeemTTL),
	}
	var fx effects
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return Minted{}, errors.New("server is shutting down")
	}
	n := 0
	for _, o := range s.tickets {
		if o.accountID == p.AccountID && o.guest == nil {
			n++
		}
	}
	if n >= MaxOutstanding {
		s.mu.Unlock()
		slog.Info("ticket: mint refused", "account", p.AccountID, "endpoint", ref.ID, "reason", "too many outstanding tickets")
		return Minted{}, ErrTooManyTickets
	}
	s.tickets[t.id] = t
	s.byToken[t.tokenHash] = t
	view := s.viewLocked(t)
	fx.audits = append(fx.audits, s.event(t, nil, audit.TicketMinted))
	fx.ownerTickets(t.accountID)
	s.mu.Unlock()
	s.apply(&fx, false)
	slog.Info("ticket: minted", "account", t.accountID, "ticket", t.id, "endpoint", t.endpointID,
		"redeemTtl", opts.RedeemTTL, "lifetime", opts.Lifetime,
		"reasonRequired", opts.ReasonRequired, "agentForward", opts.AgentForward)
	return Minted{Ticket: view, Token: token}, nil
}

// View is the owner's view of a ticket and its guest session.
type View struct {
	ID               string     `json:"id"`
	EndpointID       string     `json:"endpointId"`
	Label            string     `json:"label"`
	CreatedAt        string     `json:"createdAt"`
	ExpiresAt        string     `json:"expiresAt"`
	RedeemTTLSeconds int        `json:"redeemTtlSeconds"`
	LifetimeSeconds  int        `json:"lifetimeSeconds"`
	ReasonRequired   bool       `json:"reasonRequired"`
	AgentForward     bool       `json:"agentForward"`
	State            string     `json:"state"`
	Guest            *GuestView `json:"guest"`
}

// GuestView is the guest-session half of a View.
type GuestView struct {
	State             string  `json:"state"`
	Channel           string  `json:"channel"`
	ConfirmationCode  string  `json:"confirmationCode"`
	Reason            string  `json:"reason"`
	SourceIP          string  `json:"sourceIp"`
	UserAgent         string  `json:"userAgent"`
	RedeemedAt        string  `json:"redeemedAt"`
	AdmissionDeadline *string `json:"admissionDeadline"`
	LifetimeDeadline  *string `json:"lifetimeDeadline"`
	SessionID         *string `json:"sessionId"`
	Attempt           int     `json:"attempt"`
	Attached          bool    `json:"attached"`
	Connections       int     `json:"connections"`
}

func iso(t time.Time) string { return t.UTC().Format(clock.ISOMillis) }

func isoPtr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	v := iso(t)
	return &v
}

func (s *Service) viewLocked(t *ticket) View {
	v := View{
		ID: t.id, EndpointID: t.endpointID, Label: t.opts.Label,
		CreatedAt: iso(t.createdAt), ExpiresAt: iso(t.expiresAt),
		RedeemTTLSeconds: int(t.opts.RedeemTTL / time.Second), LifetimeSeconds: int(t.opts.Lifetime / time.Second),
		ReasonRequired: t.opts.ReasonRequired, AgentForward: t.opts.AgentForward, State: StateMinted,
	}
	if g := t.guest; g != nil {
		v.State = g.state
		gv := &GuestView{
			State: g.state, Channel: string(g.channel), ConfirmationCode: g.code, Reason: g.reason,
			SourceIP: g.sourceIP, UserAgent: g.userAgent, RedeemedAt: iso(g.redeemedAt),
			AdmissionDeadline: isoPtr(g.admissionDeadline), LifetimeDeadline: isoPtr(g.lifetimeDeadline),
			Attempt: g.attempt, Attached: g.conns > 0, Connections: g.conns,
		}
		if g.sessionID != "" {
			sid := g.sessionID
			gv.SessionID = &sid
		} else if g.attemptSession != "" && g.state == StatePending {
			sid := g.attemptSession
			gv.SessionID = &sid
		}
		v.Guest = gv
	}
	return v
}

// List returns the account's live tickets (unredeemed, or with a live
// guest session), oldest first.
func (s *Service) List(accountID string) []View {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []View{}
	for _, t := range s.tickets {
		if t.accountID == accountID {
			out = append(out, s.viewLocked(t))
		}
	}
	// Oldest first; the id breaks ties within one timestamp.
	slices.SortFunc(out, func(a, b View) int {
		if c := strings.Compare(a.CreatedAt, b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// Revoke ends a ticket in any state: an unredeemed ticket is deleted,
// anything later goes through the close path. False when the ticket is not
// the account's (or no longer exists).
func (s *Service) Revoke(accountID, ticketID string) bool {
	var fx effects
	s.mu.Lock()
	t, ok := s.tickets[ticketID]
	if !ok || t.accountID != accountID {
		s.mu.Unlock()
		return false
	}
	fx.audits = append(fx.audits, s.event(t, t.guest, audit.TicketRevoked))
	if t.guest == nil {
		s.dropTicketLocked(t)
		fx.ownerTickets(accountID)
	} else {
		s.closeLocked(t.guest, terminal.CloseTicketRevoked, &fx)
	}
	s.mu.Unlock()
	s.apply(&fx, false)
	slog.Info("ticket: revoked", "account", accountID, "ticket", ticketID)
	return true
}

func (s *Service) dropTicketLocked(t *ticket) {
	delete(s.tickets, t.id)
	if cur, ok := s.byToken[t.tokenHash]; ok && cur == t {
		delete(s.byToken, t.tokenHash)
	}
}

// --- redeem (guest) -------------------------------------------------------

// RedeemParams carry one redemption attempt. Cookie is the guest cookie the
// browser already holds ("" when none) — read only for the one-session
// guard.
type RedeemParams struct {
	Token     string
	Reason    string
	SourceIP  string
	UserAgent string
	Cookie    string
	Channel   terminal.TicketChannel
}

// Redeemed is a successful redemption: the guest cookie (returned exactly
// once) and what the waiting screen shows.
type Redeemed struct {
	Cookie           string
	CookieMaxAge     time.Duration
	ConfirmationCode string
	AttachDeadline   time.Time
	AdmissionWindow  time.Duration
	Lifetime         time.Duration
	ReasonRequired   bool
	AgentForward     bool
}

// CapacityError is ErrCapacity with a retry hint.
type CapacityError struct{ RetryAfter time.Duration }

func (e *CapacityError) Error() string { return ErrCapacity.Error() }
func (e *CapacityError) Unwrap() error { return ErrCapacity }

// HasLiveGuest reports whether cookie names a live guest session.
func (s *Service) HasLiveGuest(cookie string) bool {
	if cookie == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byCookie[hash(cookie)]
	return ok && g.state != StateClosed
}

// Redeem consumes a ticket and creates a guest session waiting for its
// first attach. Nothing is connected and no prompt is raised here.
func (s *Service) Redeem(ctx context.Context, p RedeemParams) (Redeemed, error) {
	if s.HasLiveGuest(p.Cookie) {
		slog.Info("ticket: redeem rejected", "reason", "browser holds a live guest session", "sourceIp", p.SourceIP)
		return Redeemed{}, ErrLiveGuest
	}
	if p.Channel == "" {
		p.Channel = terminal.TicketChannelWeb
	}
	h := hash(p.Token)
	now := s.clk.Now()

	s.mu.Lock()
	t := s.byToken[h]
	var snapshot ticket
	if t != nil {
		snapshot = *t
	}
	s.mu.Unlock()
	if t == nil || p.Token == "" {
		slog.Info("ticket: redeem rejected", "reason", "unknown or already used ticket", "sourceIp", p.SourceIP)
		return Redeemed{}, ErrNotFound
	}
	if !now.Before(snapshot.expiresAt) {
		s.invalidate(t, audit.TicketExpired, "expired")
		slog.Info("ticket: redeem rejected", "ticket", t.id, "reason", "expired", "sourceIp", p.SourceIP)
		return Redeemed{}, ErrNotFound
	}
	reason := util.SanitizeFreeText(p.Reason, ReasonMaxLen)
	if snapshot.opts.ReasonRequired && reason == "" {
		slog.Info("ticket: redeem rejected", "ticket", t.id, "reason", "reason required", "sourceIp", p.SourceIP)
		return Redeemed{}, ErrReasonRequired
	}
	// Eligibility recheck: the account and the endpoint must still be there.
	// Only a definite "gone" spends the ticket; a failed lookup (cancelled
	// request, database error) leaves it redeemable.
	if s.p.AccountActive != nil {
		active, err := s.p.AccountActive(ctx, snapshot.accountID)
		if err != nil {
			slog.Warn("ticket: redeem eligibility check failed", "ticket", t.id, "check", "account",
				"sourceIp", p.SourceIP, "err", err)
			return Redeemed{}, ErrUnavailable
		}
		if !active {
			s.invalidate(t, audit.TicketInvalidated, "account removed or disabled")
			slog.Info("ticket: redeem rejected", "ticket", t.id, "reason", "account removed or disabled", "sourceIp", p.SourceIP)
			return Redeemed{}, ErrNotFound
		}
	}
	ref, err := s.p.ResolveEndpoint(ctx, snapshot.endpointID, snapshot.accountID)
	if err != nil {
		slog.Warn("ticket: redeem eligibility check failed", "ticket", t.id, "check", "endpoint",
			"sourceIp", p.SourceIP, "err", err)
		return Redeemed{}, ErrUnavailable
	}
	if ref == nil {
		s.invalidate(t, audit.TicketInvalidated, "endpoint removed or disabled")
		slog.Info("ticket: redeem rejected", "ticket", t.id, "reason", "endpoint removed or disabled", "sourceIp", p.SourceIP)
		return Redeemed{}, ErrNotFound
	}

	cookie := randomToken()
	g := &guest{
		id: randomID(), t: t, cookieHash: hash(cookie), code: confirmationCode(),
		reason: reason, sourceIP: p.SourceIP,
		userAgent: util.SanitizeFreeText(p.UserAgent, UserAgentMaxLen),
		channel:   p.Channel, state: StateRedeemed,
		redeemedAt: now, attachDeadline: now.Add(AttachWindow),
	}
	var fx effects
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return Redeemed{}, ErrNotFound
	}
	// Lookup, recheck, reserve and consume under one lock: exactly one
	// concurrent redemption wins.
	if cur := s.byToken[h]; cur != t || t.guest != nil {
		s.mu.Unlock()
		slog.Info("ticket: redeem rejected", "ticket", t.id, "reason", "already redeemed", "sourceIp", p.SourceIP)
		return Redeemed{}, ErrNotFound
	}
	if live := s.liveGuestsLocked(t.accountID); live >= MaxGuestSessions {
		retry := s.retryAfterLocked(t.accountID)
		s.mu.Unlock()
		slog.Info("ticket: redeem rejected", "ticket", t.id, "reason", "guest session cap reached",
			"account", t.accountID, "sourceIp", p.SourceIP)
		return Redeemed{}, &CapacityError{RetryAfter: retry}
	}
	delete(s.byToken, h)
	t.guest = g
	s.guests[g.id] = g
	s.byCookie[g.cookieHash] = g
	fx.audits = append(fx.audits, s.event(t, g, audit.TicketRedeemed))
	fx.ownerTickets(t.accountID)
	opts := t.opts
	s.mu.Unlock()
	s.apply(&fx, false)
	slog.Info("ticket: redeemed", "account", t.accountID, "ticket", t.id, "channel", p.Channel, "sourceIp", p.SourceIP)
	return Redeemed{
		Cookie:           cookie,
		CookieMaxAge:     AttachWindow + AdmissionWindow + opts.Lifetime + ReconnectGrace,
		ConfirmationCode: g.code, AttachDeadline: g.attachDeadline,
		AdmissionWindow: AdmissionWindow, Lifetime: opts.Lifetime,
		ReasonRequired: opts.ReasonRequired, AgentForward: opts.AgentForward,
	}, nil
}

// invalidate drops an unredeemed ticket that failed a redemption check.
func (s *Service) invalidate(t *ticket, event, why string) {
	var fx effects
	s.mu.Lock()
	if _, ok := s.tickets[t.id]; !ok || t.guest != nil {
		s.mu.Unlock()
		return
	}
	s.dropTicketLocked(t)
	ev := s.event(t, nil, event)
	ev.EndReason = why
	fx.audits = append(fx.audits, ev)
	fx.ownerTickets(t.accountID)
	s.mu.Unlock()
	s.apply(&fx, false)
}

func (s *Service) liveGuestsLocked(accountID string) int {
	n := 0
	for _, g := range s.guests {
		if g.t.accountID == accountID && g.state != StateClosed {
			n++
		}
	}
	return n
}

// retryAfterLocked estimates when a guest slot frees: the earliest hard
// deadline among the account's live guest sessions.
func (s *Service) retryAfterLocked(accountID string) time.Duration {
	now := s.clk.Now()
	best := time.Duration(0)
	for _, g := range s.guests {
		if g.t.accountID != accountID || g.state == StateClosed {
			continue
		}
		var d time.Time
		switch {
		case g.state == StateOpen:
			d = g.lifetimeDeadline
		case g.admissionDeadline.IsZero():
			d = g.attachDeadline
		default:
			d = g.admissionDeadline
		}
		if left := d.Sub(now); left > 0 && (best == 0 || left < best) {
			best = left
		}
	}
	if best < time.Second {
		best = time.Second
	}
	return best
}

// --- guest connections ------------------------------------------------------

// GuestByCookie resolves a guest cookie to its live guest session id.
func (s *Service) GuestByCookie(cookie string) (string, bool) {
	if cookie == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byCookie[hash(cookie)]
	if !ok || g.state == StateClosed {
		return "", false
	}
	return g.id, true
}

// Attach registers one guest connection (the caller registered it with the
// publisher first, so the status sent here reaches it). The first attach
// opens the admission window and starts the first attempt.
func (s *Service) Attach(guestID string) error {
	var fx effects
	s.mu.Lock()
	g, ok := s.guests[guestID]
	if !ok || g.state == StateClosed {
		s.mu.Unlock()
		return ErrGone
	}
	if g.conns >= MaxConnections {
		s.mu.Unlock()
		slog.Info("ticket: guest attach refused", "ticket", g.t.id, "reason", "too many connections")
		return ErrTooManyConnections
	}
	g.conns++
	wasDetached := !g.graceDeadline.IsZero()
	g.graceDeadline = time.Time{}
	if g.admissionDeadline.IsZero() {
		g.admissionDeadline = s.clk.Now().Add(AdmissionWindow)
		fx.audits = append(fx.audits, s.event(g.t, g, audit.TicketAttached))
		slog.Info("ticket: attached", "ticket", g.t.id, "account", g.t.accountID)
		s.startAttemptLocked(g, &fx)
	} else {
		if wasDetached && g.conns == 1 {
			fx.audits = append(fx.audits, s.event(g.t, g, audit.TicketReattached))
			slog.Info("ticket: guest reattached", "ticket", g.t.id, "state", g.state)
		}
		s.publishStatusLocked(g)
		if g.state == StateOpen && s.pub != nil {
			s.pub.GuestOpen(g.id, g.sessionID)
		}
	}
	fx.ownerTickets(g.t.accountID)
	if g.sessionID != "" {
		fx.ownerSessions(g.t.accountID)
	}
	s.mu.Unlock()
	s.apply(&fx, false)
	return nil
}

// Detach unregisters one guest connection; the last one starts the
// reconnect grace.
func (s *Service) Detach(guestID string) {
	var fx effects
	s.mu.Lock()
	g, ok := s.guests[guestID]
	if !ok || g.state == StateClosed || g.conns == 0 {
		s.mu.Unlock()
		return
	}
	g.conns--
	if g.conns == 0 {
		g.graceDeadline = s.clk.Now().Add(ReconnectGrace)
		fx.audits = append(fx.audits, s.event(g.t, g, audit.TicketDetached))
		slog.Info("ticket: guest detached", "ticket", g.t.id, "state", g.state, "grace", ReconnectGrace)
		fx.ownerTickets(g.t.accountID)
		if g.sessionID != "" {
			fx.ownerSessions(g.t.accountID)
		}
	}
	s.mu.Unlock()
	s.apply(&fx, false)
}

// End is the guest's End button: close immediately.
func (s *Service) End(guestID string) {
	s.closeByID(guestID, terminal.CloseClientGuest)
}

// Retry starts a new attempt — accepted only in refused, inside the
// admission window.
func (s *Service) Retry(guestID string) {
	var fx effects
	s.mu.Lock()
	g, ok := s.guests[guestID]
	if !ok || g.state != StateRefused || !s.clk.Now().Before(g.admissionDeadline) {
		s.mu.Unlock()
		return
	}
	fx.audits = append(fx.audits, s.event(g.t, g, audit.TicketRetried))
	s.startAttemptLocked(g, &fx)
	fx.ownerTickets(g.t.accountID)
	s.mu.Unlock()
	s.apply(&fx, false)
	slog.Info("ticket: retry", "ticket", g.t.id, "attempt", g.attempt)
}

// GuestAttached reports, for a terminal session admitted by a ticket,
// whether the guest is currently attached (ok=false for any other session).
func (s *Service) GuestAttached(sessionID string) (attached, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, found := s.bySession[sessionID]
	if !found || g.state == StateClosed {
		return false, false
	}
	return g.conns > 0, true
}

// --- attempts -------------------------------------------------------------

func (s *Service) publishStatusLocked(g *guest) {
	if s.pub == nil {
		return
	}
	s.pub.GuestStatus(g.id, s.statusLocked(g))
}

func (s *Service) statusLocked(g *guest) Status {
	st := Status{State: g.state, ServerTime: iso(s.clk.Now())}
	switch g.state {
	case StateRedeemed, StatePending:
		st.State = StatePending
		st.Code = g.code
		if !g.admissionDeadline.IsZero() {
			st.AdmissionDeadline = iso(g.admissionDeadline)
		}
	case StateRefused:
		st.Code = g.code
		st.AdmissionDeadline = iso(g.admissionDeadline)
		left := int(g.admissionDeadline.Sub(s.clk.Now()).Seconds())
		if left < 0 {
			left = 0
		}
		st.RemainingSeconds = &left
		st.Message = MsgNotGranted
	case StateOpen:
		st.LifetimeDeadline = iso(g.lifetimeDeadline)
	}
	return st
}

// startAttemptLocked launches one Manager.Create for the guest session (on
// its own goroutine, bounded by the admission window via the close path).
func (s *Service) startAttemptLocked(g *guest, fx *effects) {
	g.attempt++
	n := g.attempt
	sid := terminal.GenerateSessionID()
	// Superseded attempts stay mapped until their closed event or the
	// guest's close, so a late event from one is recognized (and a stale
	// open is closed) instead of slipping past as an unknown session.
	g.attemptSession = sid
	s.bySession[sid] = g
	ctx, cancel := context.WithCancel(s.ctx)
	g.attemptCancel = cancel
	g.state = StatePending
	s.publishStatusLocked(g)
	t := g.t
	trigger := terminal.Trigger{
		Kind: terminal.SourceTicket, SourceIP: g.sourceIP, Reason: g.reason, SessionID: sid,
		Ticket: &terminal.TicketTrigger{
			TicketID: t.id, Label: t.opts.Label, Channel: g.channel, UserAgent: g.userAgent,
			ConfirmationCode: g.code, AgentForward: t.opts.AgentForward,
			LifetimeSeconds: int(t.opts.Lifetime / time.Second),
		},
	}
	go s.runAttempt(ctx, attemptParams{
		guestID: g.id, n: n, accountID: t.accountID, endpointID: t.endpointID,
		agentForward: t.opts.AgentForward, trigger: trigger,
	})
}

// attemptParams describe one admission attempt (runAttempt).
type attemptParams struct {
	guestID string
	// n is the attempt number; events of a superseded attempt are ignored.
	n                     int
	accountID, endpointID string
	// agentForward is the ticket's option (the endpoint's setting also
	// applies).
	agentForward bool
	trigger      terminal.Trigger
}

func (s *Service) runAttempt(ctx context.Context, a attemptParams) {
	ref, err := s.p.ResolveEndpoint(ctx, a.endpointID, a.accountID)
	if err != nil || ref == nil {
		if err == nil {
			// The endpoint was removed or disabled since redemption: the
			// guest session cannot be admitted any more.
			s.closeByID(a.guestID, terminal.CloseEndpointRemoved)
			return
		}
		s.attemptFailed(a.guestID, a.n, "endpoint lookup failed: "+err.Error())
		return
	}
	ep := *ref
	// Agent forwarding never goes beyond the endpoint's own setting.
	ep.AgentForward = ep.AgentForward && a.agentForward
	sess, err := s.p.Manager.Create(ctx, ep, a.accountID, a.trigger)
	if err != nil {
		s.attemptFailed(a.guestID, a.n, err.Error())
		return
	}
	// Backstop: a session that went live for a guest session that is gone,
	// or for an attempt that is no longer current, must not stay open.
	s.mu.Lock()
	g, ok := s.guests[a.guestID]
	live := ok && g.state == StateOpen && g.sessionID == sess.SessionID
	s.mu.Unlock()
	if !live {
		s.p.Manager.Close(sess.SessionID, terminal.CloseTicketNotAdmitted)
	}
}

// attemptFailed moves the guest to refused when attempt n is still the
// current, unadmitted one (idempotent: the Manager's closed broadcast for a
// failed create usually got here first).
func (s *Service) attemptFailed(guestID string, n int, why string) {
	var fx effects
	s.mu.Lock()
	g, ok := s.guests[guestID]
	if !ok || g.attempt != n || g.state != StatePending {
		s.mu.Unlock()
		return
	}
	s.refuseLocked(g, why, &fx)
	s.mu.Unlock()
	s.apply(&fx, false)
}

func (s *Service) refuseLocked(g *guest, why string, fx *effects) {
	g.state = StateRefused
	if g.attemptCancel != nil {
		fx.cancels = append(fx.cancels, g.attemptCancel)
		g.attemptCancel = nil
	}
	ev := s.event(g.t, g, audit.TicketAttemptFailed)
	ev.EndReason = why
	fx.audits = append(fx.audits, ev)
	fx.ownerTickets(g.t.accountID)
	s.publishStatusLocked(g)
	slog.Info("ticket: attempt failed", "ticket", g.t.id, "attempt", g.attempt, "reason", why)
}

// onStatus is the Manager status hook: admission, and the end of an
// attempt or of an admitted session. Events of an attempt that is no longer
// current are ignored.
func (s *Service) onStatus(ev terminal.StatusEvent) {
	var fx effects
	s.mu.Lock()
	g, ok := s.bySession[ev.SessionID]
	if !ok {
		s.mu.Unlock()
		return
	}
	current := g.attemptSession == ev.SessionID
	switch ev.Status {
	case terminal.StatusOpen:
		if current && g.state == StatePending {
			now := s.clk.Now()
			g.state = StateOpen
			g.sessionID = ev.SessionID
			g.openedAt = now
			g.lifetimeDeadline = now.Add(g.t.opts.Lifetime)
			s.publishStatusLocked(g)
			if s.pub != nil {
				s.pub.GuestOpen(g.id, g.sessionID)
			}
			fx.audits = append(fx.audits, s.event(g.t, g, audit.TicketAdmitted))
			fx.ownerTickets(g.t.accountID)
			fx.ownerSessions(g.t.accountID)
			slog.Info("ticket: admitted", "ticket", g.t.id, "account", g.t.accountID,
				"session", ev.SessionID, "attempt", g.attempt)
		} else {
			// A stale attempt went live after all: it must not stay open.
			delete(s.bySession, ev.SessionID)
			fx.closes = append(fx.closes, closeReq{ev.SessionID, terminal.CloseTicketNotAdmitted})
		}
	case terminal.StatusClosed, terminal.StatusError:
		if !current {
			delete(s.bySession, ev.SessionID)
			break
		}
		switch g.state {
		case StateOpen:
			reason := ev.Reason
			if reason == "" {
				reason = terminal.CloseServerHangup
			}
			g.attemptSession = "" // the terminal session is already ending
			s.closeLocked(g, reason, &fx)
		case StatePending:
			why := string(ev.Reason)
			if why == "" {
				why = "connection closed during setup"
			}
			s.refuseLocked(g, why, &fx)
		}
	}
	s.mu.Unlock()
	s.apply(&fx, true)
}

// --- the one close path ---------------------------------------------------

func (s *Service) closeByID(guestID string, reason terminal.CloseReason) {
	var fx effects
	s.mu.Lock()
	g, ok := s.guests[guestID]
	if !ok {
		s.mu.Unlock()
		return
	}
	s.closeLocked(g, reason, &fx)
	s.mu.Unlock()
	s.apply(&fx, false)
}

// closeLocked is the one close path. It closes the terminal session (or
// cancels the setup, which cancels the connection's pending approvals and
// clears their toasts), deletes the guest credential, sends the final
// status and closes the guest connections, releases the capacity
// reservation, and writes the audit row.
func (s *Service) closeLocked(g *guest, reason terminal.CloseReason, fx *effects) {
	if g.state == StateClosed {
		return
	}
	prev := g.state
	g.state = StateClosed
	if g.attemptCancel != nil {
		fx.cancels = append(fx.cancels, g.attemptCancel)
		g.attemptCancel = nil
	}
	if g.attemptSession != "" && (prev == StatePending || prev == StateOpen) {
		fx.closes = append(fx.closes, closeReq{g.attemptSession, reason})
	}
	for sid, owner := range s.bySession {
		if owner == g {
			delete(s.bySession, sid)
		}
	}
	delete(s.byCookie, g.cookieHash)
	delete(s.guests, g.id)
	s.dropTicketLocked(g.t)

	msg := MsgEnded
	if prev != StateOpen {
		msg = MsgNotGranted
	}
	if s.pub != nil {
		s.pub.GuestClose(g.id, Status{State: StateClosed, Message: msg, ServerTime: iso(s.clk.Now())})
	}
	now := s.clk.Now()
	ev := s.event(g.t, g, audit.TicketEnded)
	ev.EndReason = string(reason)
	if g.sessionID != "" {
		ev.SessionID = g.sessionID
		d := now.Sub(g.openedAt).Milliseconds()
		ev.DurationMs = &d
	}
	fx.audits = append(fx.audits, ev)
	fx.ownerTickets(g.t.accountID)
	if prev == StateOpen || prev == StatePending {
		fx.ownerSessions(g.t.accountID)
	}
	if prev == StateRedeemed && reason == terminal.CloseTicketUnattached {
		slog.Info("ticket: redeemed but never attached", "ticket", g.t.id, "account", g.t.accountID)
	}
	attrs := []any{"ticket", g.t.id, "account", g.t.accountID, "reason", reason, "state", prev}
	if !g.openedAt.IsZero() {
		attrs = append(attrs, "dur", now.Sub(g.openedAt).Round(time.Second))
	}
	slog.Info("ticket: ended", attrs...)
}

// CloseForAccount ends every ticket and guest session of an account
// (account deleted or disabled).
func (s *Service) CloseForAccount(accountID string, reason terminal.CloseReason) {
	s.closeMatching(func(t *ticket) bool { return t.accountID == accountID }, reason)
}

// CloseForEndpoint ends every ticket and guest session for an endpoint
// (endpoint deleted or disabled).
func (s *Service) CloseForEndpoint(accountID, endpointID string) {
	s.closeMatching(func(t *ticket) bool {
		return t.accountID == accountID && t.endpointID == endpointID
	}, terminal.CloseEndpointRemoved)
}

func (s *Service) closeMatching(match func(*ticket) bool, reason terminal.CloseReason) {
	var fx effects
	s.mu.Lock()
	for _, t := range s.tickets {
		if !match(t) {
			continue
		}
		if t.guest == nil {
			s.dropTicketLocked(t)
			ev := s.event(t, nil, audit.TicketInvalidated)
			ev.EndReason = string(reason)
			fx.audits = append(fx.audits, ev)
			fx.ownerTickets(t.accountID)
		} else {
			s.closeLocked(t.guest, reason, &fx)
		}
	}
	s.mu.Unlock()
	s.apply(&fx, false)
}

// Sweep enforces every deadline: redeem TTL, attach window, admission
// window, session lifetime, reconnect grace. The janitor calls it; tests
// call it after advancing a fake clock.
func (s *Service) Sweep() {
	var fx effects
	now := s.clk.Now()
	s.mu.Lock()
	for _, t := range s.tickets {
		if t.guest == nil && !now.Before(t.expiresAt) {
			s.dropTicketLocked(t)
			fx.audits = append(fx.audits, s.event(t, nil, audit.TicketExpired))
			fx.ownerTickets(t.accountID)
			slog.Info("ticket: expired", "ticket", t.id, "account", t.accountID)
		}
	}
	for _, g := range s.guests {
		switch {
		case g.state == StateRedeemed && g.admissionDeadline.IsZero() && !now.Before(g.attachDeadline):
			s.closeLocked(g, terminal.CloseTicketUnattached, &fx)
		case (g.state == StatePending || g.state == StateRefused) && !now.Before(g.admissionDeadline):
			s.closeLocked(g, terminal.CloseTicketNotAdmitted, &fx)
		case g.state == StateOpen && !now.Before(g.lifetimeDeadline):
			s.closeLocked(g, terminal.CloseTicketLifetime, &fx)
		case g.conns == 0 && !g.graceDeadline.IsZero() && !now.Before(g.graceDeadline):
			s.closeLocked(g, terminal.CloseGuestDisconnected, &fx)
		}
	}
	s.mu.Unlock()
	s.apply(&fx, false)
}

// RunJanitor sweeps every interval until ctx is done.
func (s *Service) RunJanitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

// Close ends everything (shutdown) and detaches from the Manager.
func (s *Service) Close() {
	var fx effects
	s.mu.Lock()
	s.closed = true
	for _, t := range s.tickets {
		if t.guest != nil {
			s.closeLocked(t.guest, terminal.CloseShutdown, &fx)
		} else {
			s.dropTicketLocked(t)
		}
	}
	s.mu.Unlock()
	s.apply(&fx, false)
	if s.unsub != nil {
		s.unsub()
	}
	s.cancel()
}

// --- helpers ----------------------------------------------------------------

func hash(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func randomID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func confirmationCode() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	out := make([]byte, len(b))
	for i, v := range b {
		// 32-symbol alphabet: the low 5 bits of a random byte are uniform.
		out[i] = codeAlphabet[int(v&0x1f)]
	}
	return string(out)
}
