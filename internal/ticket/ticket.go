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
	// MaxAttempts caps admission attempts per guest session (the first one
	// plus "Ask again"). Each attempt prompts the owner and dials the
	// endpoint, so a ticket holder must not be able to repeat it at will.
	// When the last one is refused, the guest session closes.
	MaxAttempts = 3
	// RetryCooldown is the minimum wait after a refusal before "Ask again".
	RetryCooldown = 15 * time.Second
	// ClosedRetention and MaxClosedPerAccount bound how long, and how many,
	// closed guest sessions stay in the owner's list (the same limits as the
	// Manager's ended terminal sessions); the audit log keeps them for good.
	ClosedRetention     = 5 * time.Minute
	MaxClosedPerAccount = 10
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

// MsgEnded is the one closed text a guest sees, whatever ended its session
// (the real reason is in the owner's audit log).
const MsgEnded = "The session has ended."

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
	// ErrAlreadyEnded: revoke of a ticket whose guest session already
	// ended. Nothing changes; the ticket leaves the list on its own
	// (ClosedRetention), and the audit already has its end.
	ErrAlreadyEnded = errors.New("ticket already ended")
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
	// RetryAt (refused): when "Ask again" is accepted; AttemptsLeft
	// (refused): how many more attempts the guest has.
	RetryAt      string `json:"retryAt,omitempty"`
	AttemptsLeft *int   `json:"attemptsLeft,omitempty"`
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
	// endedAt / endReason: set when the guest session closed; the ticket
	// then stays listed (state closed) until the retention limits drop it.
	endedAt   time.Time
	endReason terminal.CloseReason
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
	retryAt        time.Time // when "Ask again" is allowed (refused only)
	attemptSession string
	attemptCancel  context.CancelFunc
	sessionID      string // the admitted terminal session
}

// Service is the ticket lifecycle owner.
type Service struct {
	p   Params
	clk clock.Clock
	// eventIDs orders audit rows by when events happen (see event).
	eventIDs audit.OrderedIDs

	// Batched owner notifications for guest attach/detach (notifySoon).
	notifyMu      sync.Mutex
	notifyPending map[string]bool // account -> session list too
	notifyArmed   bool
	ctx           context.Context
	cancel        context.CancelFunc
	unsub         func()

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
func (s *Service) apply(fx *effects) {
	for _, c := range fx.cancels {
		c()
	}
	// Audit rows and owner notifications first: they are quick and must not
	// wait behind a terminal close. A close can block for seconds (a wedged
	// transport, up to the Manager's join timeout), so each one runs on its
	// own goroutine — the janitor and every other caller move on at once.
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
	for _, c := range fx.closes {
		go s.p.Manager.Close(c.sessionID, c.reason)
	}
}

// event builds an audit event, stamped with its time and a time-ordered id
// now — callers hold s.mu, so ids follow the order events happen in, even
// though apply writes them after the lock is released.
func (s *Service) event(t *ticket, g *guest, name string) audit.TicketEvent {
	at := s.clk.Now()
	ev := audit.TicketEvent{
		ID: s.eventIDs.Next(at), At: at,
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
	s.apply(&fx)
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
	// EndedAt / EndReason: set once the guest session closed (state closed).
	EndedAt   *string `json:"endedAt"`
	EndReason *string `json:"endReason"`
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
	if !t.endedAt.IsZero() {
		v.EndedAt = isoPtr(t.endedAt)
		why := string(t.endReason)
		v.EndReason = &why
	}
	return v
}

// List returns the account's tickets — unredeemed, with a live guest
// session, or with a recently closed one (ClosedRetention) — oldest first.
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

// Revoke ends a live ticket: an unredeemed one is deleted, a redeemed one
// goes through the close path. ErrNotFound when the ticket is not the
// account's (or no longer listed); ErrAlreadyEnded when its guest session
// already ended — nothing is removed then.
func (s *Service) Revoke(accountID, ticketID string) error {
	var fx effects
	s.mu.Lock()
	t, ok := s.tickets[ticketID]
	if !ok || t.accountID != accountID {
		s.mu.Unlock()
		return ErrNotFound
	}
	if !t.endedAt.IsZero() {
		s.mu.Unlock()
		slog.Info("ticket: revoke ignored", "account", accountID, "ticket", ticketID, "reason", "already ended")
		return ErrAlreadyEnded
	}
	fx.audits = append(fx.audits, s.event(t, t.guest, audit.TicketRevoked))
	if t.guest == nil {
		s.dropTicketLocked(t)
		fx.ownerTickets(accountID)
	} else {
		s.closeLocked(t.guest, terminal.CloseTicketRevoked, &fx)
	}
	s.mu.Unlock()
	s.apply(&fx)
	slog.Info("ticket: revoked", "account", accountID, "ticket", ticketID)
	return nil
}

// retainClosedLocked keeps a ticket whose guest session just closed in the
// owner's list for ClosedRetention, dropping the account's oldest closed
// ones beyond MaxClosedPerAccount.
func (s *Service) retainClosedLocked(t *ticket, reason terminal.CloseReason) {
	t.endedAt = s.clk.Now()
	t.endReason = reason
	var closed []*ticket
	for _, o := range s.tickets {
		if o.accountID == t.accountID && !o.endedAt.IsZero() {
			closed = append(closed, o)
		}
	}
	if over := len(closed) - MaxClosedPerAccount; over > 0 {
		slices.SortFunc(closed, func(a, b *ticket) int { return a.endedAt.Compare(b.endedAt) })
		for _, o := range closed[:over] {
			s.dropClosedLocked(o, "evicted")
		}
	}
}

// dropClosedLocked removes an ended ticket from the owner's list and logs
// why (expired, evicted, endpoint or account removed).
func (s *Service) dropClosedLocked(t *ticket, why string) {
	s.dropTicketLocked(t)
	slog.Info("ticket: removed from list", "account", t.accountID, "ticket", t.id, "reason", why)
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
	// ReplaceCurrent ends the guest session the browser's cookie names (if
	// any) in the same step that consumes the ticket, instead of answering
	// ErrLiveGuest. The old session is never attached for it, so no owner
	// prompt is raised for it.
	ReplaceCurrent bool
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

// HasLiveGuestForEndpoint reports whether the account has a live guest
// session (any state before closed) on the endpoint.
func (s *Service) HasLiveGuestForEndpoint(accountID, endpointID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.guests {
		if g.state != StateClosed && g.t.accountID == accountID && g.t.endpointID == endpointID {
			return true
		}
	}
	return false
}

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

// Checked is what a guest page may learn about a usable ticket before
// redeeming it: whether it must ask for a reason. Nothing else (no
// endpoint, no owner) leaves the service.
type Checked struct {
	ReasonRequired bool
}

// Check reports whether a ticket can still be redeemed, without consuming it
// (the guest page asks before showing the form). It applies the redeem-time
// checks (unknown, used, revoked, expired, account or endpoint gone), so
// ErrNotFound means "redeem would fail too". Redeem additionally rechecks
// expiry at the moment it consumes the ticket, so a link that expires
// between the two can still be refused.
func (s *Service) Check(ctx context.Context, token, sourceIP string) (Checked, error) {
	_, opts, err := s.usable(ctx, token, "check", sourceIP)
	if err != nil {
		return Checked{}, err
	}
	return Checked{ReasonRequired: opts.ReasonRequired}, nil
}

// usable looks a ticket up for Check and Redeem and applies the shared
// checks. A definite "gone" (expired, account or endpoint removed) spends the
// ticket; a failed lookup (cancelled request, database error) is
// ErrUnavailable and leaves it alone. op names the caller in logs.
func (s *Service) usable(ctx context.Context, token, op, sourceIP string) (*ticket, Options, error) {
	rejected := "ticket: " + op + " rejected"
	s.mu.Lock()
	t := s.byToken[hash(token)]
	var snapshot ticket
	if t != nil {
		snapshot = *t
	}
	s.mu.Unlock()
	if t == nil || token == "" {
		slog.Info(rejected, "reason", "unknown or already used ticket", "sourceIp", sourceIP)
		return nil, Options{}, ErrNotFound
	}
	if !s.clk.Now().Before(snapshot.expiresAt) {
		s.invalidate(t, audit.TicketExpired, "expired")
		slog.Info(rejected, "ticket", t.id, "reason", "expired", "sourceIp", sourceIP)
		return nil, Options{}, ErrNotFound
	}
	if s.p.AccountActive != nil {
		active, err := s.p.AccountActive(ctx, snapshot.accountID)
		if err != nil {
			slog.Warn("ticket: eligibility check failed", "op", op, "ticket", t.id, "check", "account",
				"sourceIp", sourceIP, "err", err)
			return nil, Options{}, ErrUnavailable
		}
		if !active {
			s.invalidate(t, audit.TicketInvalidated, "account removed or disabled")
			slog.Info(rejected, "ticket", t.id, "reason", "account removed or disabled", "sourceIp", sourceIP)
			return nil, Options{}, ErrNotFound
		}
	}
	ref, err := s.p.ResolveEndpoint(ctx, snapshot.endpointID, snapshot.accountID)
	if err != nil {
		slog.Warn("ticket: eligibility check failed", "op", op, "ticket", t.id, "check", "endpoint",
			"sourceIp", sourceIP, "err", err)
		return nil, Options{}, ErrUnavailable
	}
	if ref == nil {
		s.invalidate(t, audit.TicketInvalidated, "endpoint removed or disabled")
		slog.Info(rejected, "ticket", t.id, "reason", "endpoint removed or disabled", "sourceIp", sourceIP)
		return nil, Options{}, ErrNotFound
	}
	return t, snapshot.opts, nil
}

// Redeem consumes a ticket and creates a guest session waiting for its
// first attach. Nothing is connected and no prompt is raised here.
func (s *Service) Redeem(ctx context.Context, p RedeemParams) (Redeemed, error) {
	// Early exit before any lookup; repeated under the lock below, where it
	// is authoritative.
	if !p.ReplaceCurrent && s.HasLiveGuest(p.Cookie) {
		slog.Info("ticket: redeem rejected", "reason", "browser holds a live guest session", "sourceIp", p.SourceIP)
		return Redeemed{}, ErrLiveGuest
	}
	if p.Channel == "" {
		p.Channel = terminal.TicketChannelWeb
	}
	h := hash(p.Token)
	t, opts, err := s.usable(ctx, p.Token, "redeem", p.SourceIP)
	if err != nil {
		return Redeemed{}, err
	}
	reason := util.SanitizeFreeText(p.Reason, ReasonMaxLen)
	if opts.ReasonRequired && reason == "" {
		slog.Info("ticket: redeem rejected", "ticket", t.id, "reason", "reason required", "sourceIp", p.SourceIP)
		return Redeemed{}, ErrReasonRequired
	}

	cookie := randomToken()
	g := &guest{
		id: randomID(), t: t, cookieHash: hash(cookie), code: confirmationCode(),
		reason: reason, sourceIP: p.SourceIP,
		userAgent: util.SanitizeFreeText(p.UserAgent, UserAgentMaxLen),
		channel:   p.Channel, state: StateRedeemed,
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
	// The eligibility lookups above ran without the lock and can take a
	// while: the ticket may have expired meanwhile. Recheck at the moment of
	// consumption, and count the attach window from it.
	now := s.clk.Now()
	if !now.Before(t.expiresAt) {
		s.mu.Unlock()
		// The same drop, audit row and owner notification as an expiry seen
		// before the lookups (usable).
		s.invalidate(t, audit.TicketExpired, "expired")
		slog.Info("ticket: redeem rejected", "ticket", t.id, "reason", "expired", "sourceIp", p.SourceIP)
		return Redeemed{}, ErrNotFound
	}
	g.redeemedAt, g.attachDeadline = now, now.Add(AttachWindow)
	// One guest session per browser, checked in the step that consumes the
	// ticket: two concurrent redemptions with the same cookie cannot both
	// pass. (Two first-time redemptions without a cookie cannot be told
	// apart; the loser's cookie is overwritten and its unattached session
	// drops after the attach window.)
	var replaced *guest
	if p.Cookie != "" {
		if old, ok := s.byCookie[hash(p.Cookie)]; ok && old.state != StateClosed {
			if !p.ReplaceCurrent {
				s.mu.Unlock()
				slog.Info("ticket: redeem rejected", "reason", "browser holds a live guest session", "sourceIp", p.SourceIP)
				return Redeemed{}, ErrLiveGuest
			}
			replaced = old
		}
	}
	live := s.liveGuestsLocked(t.accountID)
	if replaced != nil && replaced.t.accountID == t.accountID {
		live-- // its slot is freed below
	}
	if live >= MaxGuestSessions {
		// Checked before the replaced session is closed: a rejected
		// redemption leaves the browser's current session alone.
		retry := s.retryAfterLocked(t.accountID)
		s.mu.Unlock()
		slog.Info("ticket: redeem rejected", "ticket", t.id, "reason", "guest session cap reached",
			"account", t.accountID, "sourceIp", p.SourceIP)
		return Redeemed{}, &CapacityError{RetryAfter: retry}
	}
	if replaced != nil {
		slog.Info("ticket: guest session replaced", "ticket", replaced.t.id, "by", t.id, "sourceIp", p.SourceIP)
		s.closeLocked(replaced, terminal.CloseClientGuest, &fx)
	}
	delete(s.byToken, h)
	t.guest = g
	s.guests[g.id] = g
	s.byCookie[g.cookieHash] = g
	fx.audits = append(fx.audits, s.event(t, g, audit.TicketRedeemed))
	fx.ownerTickets(t.accountID)
	opts = t.opts
	s.mu.Unlock()
	s.apply(&fx)
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
	s.apply(&fx)
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
	if reason, expired := expiredLocked(g, s.clk.Now()); expired {
		// Past a deadline (e.g. the reconnect grace): the attach must not
		// revive it; end it now instead of waiting for the janitor.
		s.closeLocked(g, reason, &fx)
		s.mu.Unlock()
		s.apply(&fx)
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
		fx.ownerTickets(g.t.accountID)
	} else {
		reattached := wasDetached && g.conns == 1
		if reattached {
			fx.audits = append(fx.audits, s.event(g.t, g, audit.TicketReattached))
			slog.Info("ticket: guest reattached", "ticket", g.t.id, "state", g.state)
		}
		s.publishStatusLocked(g)
		if g.state == StateOpen && s.pub != nil {
			s.pub.GuestOpen(g.id, g.sessionID)
		}
		// Only the attached flag flipping changes what the owner sees (a
		// second tab does not), and a flapping connection is batched.
		if reattached {
			defer s.notifySoon(g.t.accountID, g.sessionID != "")
		}
	}
	s.mu.Unlock()
	s.apply(&fx)
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
		defer s.notifySoon(g.t.accountID, g.sessionID != "")
	}
	s.mu.Unlock()
	s.apply(&fx)
}

// attachNotifyDelay batches the owner notifications of guest attach/detach
// flips: a guest on a flaky link reconnects every few seconds, and each flip
// would otherwise refetch the ticket list and resend the session list in
// every owner tab.
const attachNotifyDelay = time.Second

// notifySoon queues an owner notification for the account (tickets, and the
// session list when sessions is set) and sends all queued ones together
// after attachNotifyDelay.
func (s *Service) notifySoon(accountID string, sessions bool) {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	if s.notifyPending == nil {
		s.notifyPending = map[string]bool{}
	}
	s.notifyPending[accountID] = s.notifyPending[accountID] || sessions
	if !s.notifyArmed {
		s.notifyArmed = true
		time.AfterFunc(attachNotifyDelay, s.flushNotify)
	}
}

func (s *Service) flushNotify() {
	s.notifyMu.Lock()
	pending := s.notifyPending
	s.notifyPending = nil
	s.notifyArmed = false
	s.notifyMu.Unlock()
	if s.p.Notifier == nil {
		return
	}
	for acc, sessions := range pending {
		s.p.Notifier.TicketsChanged(acc)
		if sessions {
			s.p.Notifier.SessionsChanged(acc)
		}
	}
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
	now := s.clk.Now()
	if !ok || g.state != StateRefused {
		s.mu.Unlock()
		return
	}
	if reason, expired := expiredLocked(g, now); expired {
		s.closeLocked(g, reason, &fx)
		s.mu.Unlock()
		s.apply(&fx)
		return
	}
	if now.Before(g.retryAt) {
		// The page knows retryAt and keeps the button disabled until then;
		// only a script sends this early. Drop it quietly: no Info log and no
		// status resend per frame, so repeating it costs nothing.
		ticketID := g.t.id
		s.mu.Unlock()
		slog.Debug("ticket: retry ignored", "ticket", ticketID, "reason", "cooldown")
		return
	}
	fx.audits = append(fx.audits, s.event(g.t, g, audit.TicketRetried))
	s.startAttemptLocked(g, &fx)
	fx.ownerTickets(g.t.accountID)
	ticketID, attempt := g.t.id, g.attempt
	s.mu.Unlock()
	s.apply(&fx)
	slog.Info("ticket: retry", "ticket", ticketID, "attempt", attempt)
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
		st.RetryAt = iso(g.retryAt)
		attemptsLeft := MaxAttempts - g.attempt
		st.AttemptsLeft = &attemptsLeft
		st.Message = "Access was not granted."
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
	s.apply(&fx)
}

func (s *Service) refuseLocked(g *guest, why string, fx *effects) {
	if g.attemptCancel != nil {
		fx.cancels = append(fx.cancels, g.attemptCancel)
		g.attemptCancel = nil
	}
	ev := s.event(g.t, g, audit.TicketAttemptFailed)
	ev.EndReason = why
	fx.audits = append(fx.audits, ev)
	slog.Info("ticket: attempt failed", "ticket", g.t.id, "attempt", g.attempt, "reason", why)
	// Truncated to the millisecond the frame carries, so the advertised
	// retryAt is exactly the enforced one.
	retryAt := s.clk.Now().Add(RetryCooldown).Truncate(time.Millisecond)
	if g.attempt >= MaxAttempts || !retryAt.Before(g.admissionDeadline) {
		// No attempt left, or none that could start before the admission
		// window ends: nothing more the guest can do.
		g.attemptSession = ""
		s.closeLocked(g, terminal.CloseTicketNotAdmitted, fx)
		return
	}
	g.state = StateRefused
	g.retryAt = retryAt
	fx.ownerTickets(g.t.accountID)
	s.publishStatusLocked(g)
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
			if reason, expired := expiredLocked(g, now); expired {
				// Approved after the admission window closed: no admission.
				// The close path also closes the session that just went live.
				s.closeLocked(g, reason, &fx)
				break
			}
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
			// A pending attempt's session never went live: Manager.Create
			// broadcasts this closed (transport-error) just before it
			// returns the real error to runAttempt, which records it via
			// attemptFailed. Refusing here would audit every failure as
			// transport-error and hide an owner's denial.
		}
	}
	s.mu.Unlock()
	s.apply(&fx)
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
	s.apply(&fx)
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
	// A closed guest session stays listed for a while: it must not claim
	// connections (the sockets are being closed now).
	g.conns = 0
	g.graceDeadline = time.Time{}
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
	s.retainClosedLocked(g.t, reason)

	if s.pub != nil {
		s.pub.GuestClose(g.id, Status{State: StateClosed, Message: MsgEnded, ServerTime: iso(s.clk.Now())})
	}
	now := s.clk.Now()
	ev := s.event(g.t, g, audit.TicketEnded)
	ev.EndReason = string(reason)
	if g.sessionID != "" {
		ev.SessionID = g.sessionID
		d := now.Sub(g.openedAt).Milliseconds()
		ev.DurationMs = &d
	}
	if reason != terminal.CloseAccountDeleted {
		// An account's audit rows go with the account (ON DELETE CASCADE):
		// there is nothing to write them into, only a failed insert to log.
		fx.audits = append(fx.audits, ev)
	}
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
		if !t.endedAt.IsZero() {
			// Already closed: its account or endpoint is gone, so it leaves
			// the list now.
			s.dropClosedLocked(t, string(reason))
			fx.ownerTickets(t.accountID)
			continue
		}
		if t.guest == nil {
			s.dropTicketLocked(t)
			if reason != terminal.CloseAccountDeleted { // rows cascade with the account
				ev := s.event(t, nil, audit.TicketInvalidated)
				ev.EndReason = string(reason)
				fx.audits = append(fx.audits, ev)
			}
			fx.ownerTickets(t.accountID)
		} else {
			s.closeLocked(t.guest, reason, &fx)
		}
	}
	s.mu.Unlock()
	s.apply(&fx)
}

// Sweep enforces every deadline: redeem TTL, attach window, admission
// window, session lifetime, reconnect grace. The janitor calls it; tests
// call it after advancing a fake clock.
func (s *Service) Sweep() {
	var fx effects
	now := s.clk.Now()
	s.mu.Lock()
	for _, t := range s.tickets {
		if !t.endedAt.IsZero() && now.Sub(t.endedAt) >= ClosedRetention {
			s.dropClosedLocked(t, "expired")
			fx.ownerTickets(t.accountID)
			continue
		}
		if t.guest == nil && !now.Before(t.expiresAt) {
			s.dropTicketLocked(t)
			ev := s.event(t, nil, audit.TicketExpired)
			ev.EndReason = "expired" // the same shape as the check/redeem path
			fx.audits = append(fx.audits, ev)
			fx.ownerTickets(t.accountID)
			slog.Info("ticket: expired", "ticket", t.id, "account", t.accountID)
		}
	}
	for _, g := range s.guests {
		if reason, expired := expiredLocked(g, now); expired {
			s.closeLocked(g, reason, &fx)
		}
	}
	s.mu.Unlock()
	s.apply(&fx)
}

// expiredLocked reports whether a guest session is past one of its
// deadlines, and the close reason. The janitor enforces it periodically;
// every transition that would extend access (an attach, an admission, a
// retry) checks it first, so access never outlives a deadline just because
// the janitor has not run yet.
func expiredLocked(g *guest, now time.Time) (terminal.CloseReason, bool) {
	switch {
	case g.state == StateRedeemed && g.admissionDeadline.IsZero() && !now.Before(g.attachDeadline):
		return terminal.CloseTicketUnattached, true
	case (g.state == StatePending || g.state == StateRefused) && !now.Before(g.admissionDeadline):
		return terminal.CloseTicketNotAdmitted, true
	case g.state == StateOpen && !now.Before(g.lifetimeDeadline):
		return terminal.CloseTicketLifetime, true
	case g.conns == 0 && !g.graceDeadline.IsZero() && !now.Before(g.graceDeadline):
		return terminal.CloseGuestDisconnected, true
	}
	return "", false
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
		if t.guest != nil && t.endedAt.IsZero() {
			s.closeLocked(t.guest, terminal.CloseShutdown, &fx)
		}
		s.dropTicketLocked(t)
	}
	s.mu.Unlock()
	s.apply(&fx)
	if s.unsub != nil {
		s.unsub()
	}
	s.cancel()
}

// --- helpers ----------------------------------------------------------------

func hash(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// crypto/rand.Read never returns an error (Go 1.24+: it crashes the
// program instead of handing out weak randomness), so none is checked.

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
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
