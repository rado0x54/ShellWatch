// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package approval is the human-in-the-loop pending-action layer (port of
// src/pending-action/ + signing-bridge.ts). The Store holds actions with a
// 60s TTL; the Broker (broker.go) is the SignBroker sshx signers block on.
// Notification channels fan an action out to the account's browsers.
package approval

import (
	"sync"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/signing"
)

// ActionTTL is how long a pending action awaits approval (ACTION_TTL_MS).
const ActionTTL = 60 * time.Second

// ActionType discriminates the two action kinds.
type ActionType string

const (
	TypeWebAuthnSign ActionType = "webauthn-sign"
	TypeKeyApprove   ActionType = "key-approve"
)

// Status is the in-memory action status (PendingActionStatus).
type Status string

const (
	StatusPending   Status = "pending"
	StatusCompleted Status = "completed"
	StatusExpired   Status = "expired"
	StatusDenied    Status = "denied"
)

// Context is the discriminated source context (SignRequestContext).
type Context struct {
	Source          string `json:"source"`
	EndpointLabel   string `json:"endpointLabel,omitempty"`
	EndpointAddress string `json:"endpointAddress,omitempty"`
	SessionID       string `json:"sessionId,omitempty"`
	SourceIP        string `json:"sourceIp,omitempty"`
	ClientHostname  string `json:"clientHostname,omitempty"`
	ClientOS        string `json:"clientOs,omitempty"`
	ClientVersion   string `json:"clientVersion,omitempty"`
	// Trigger metadata (endpoint-auth).
	TriggerKind   string `json:"-"`
	MCPReason     string `json:"-"`
	MCPClientName string `json:"-"`
	MCPClientVer  string `json:"-"`
}

// Action is a pending human-in-the-loop approval.
type Action struct {
	ID           string
	AccountID    string
	Type         ActionType
	Status       Status
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Context      Context
	RedirectTo   string
	ConnectionID string

	// webauthn-sign fields.
	CredentialID     string
	Challenge        string // standard base64 of DataToSign
	RpID             string
	PasskeyLabel     string
	UserVerification string

	// key-approve fields.
	KeyLabel       string
	KeyFingerprint string

	// resolution plumbing (not serialized).
	resolveSign func(signing.SignResponse)
	resolveKey  func()
	reject      func(error)
}

// CreateParams are the fields a caller supplies (store adds id/status/times).
type CreateParams struct {
	AccountID        string
	Type             ActionType
	Context          Context
	RedirectTo       string
	ConnectionID     string
	CredentialID     string
	Challenge        string
	RpID             string
	PasskeyLabel     string
	UserVerification string
	KeyLabel         string
	KeyFingerprint   string
	ResolveSign      func(signing.SignResponse)
	ResolveKey       func()
	Reject           func(error)
}

// Outcome is the richer audit label (SigningRequestOutcome).
type Outcome string

const (
	OutcomeApproved  Outcome = "approved"
	OutcomeDenied    Outcome = "denied"
	OutcomeExpired   Outcome = "expired"
	OutcomeCancelled Outcome = "cancelled"
)

// ResolvedEvent is emitted on a terminal transition (audit subscribes).
type ResolvedEvent struct {
	Action       *Action
	Outcome      Outcome
	ResolvedAt   time.Time
	CancelReason string
}

// Store is the in-memory pending-action registry.
type Store struct {
	mu      sync.Mutex
	actions map[string]*Action
	clk     clock.Clock
	newID   func() string

	createdSubs  []func(*Action)
	resolvedSubs []func(ResolvedEvent)
}

// NewStore builds the store. newID generates action ids (UUID).
func NewStore(clk clock.Clock, newID func() string) *Store {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Store{actions: map[string]*Action{}, clk: clk, newID: newID}
}

// OnCreated / OnResolved register audit hooks.
func (s *Store) OnCreated(fn func(*Action))        { s.createdSubs = append(s.createdSubs, fn) }
func (s *Store) OnResolved(fn func(ResolvedEvent)) { s.resolvedSubs = append(s.resolvedSubs, fn) }

// Create registers a new pending action and fires created hooks.
func (s *Store) Create(p CreateParams) *Action {
	now := s.clk.Now()
	a := &Action{
		ID: s.newID(), AccountID: p.AccountID, Type: p.Type, Status: StatusPending,
		CreatedAt: now, ExpiresAt: now.Add(ActionTTL), Context: p.Context, RedirectTo: p.RedirectTo,
		ConnectionID: p.ConnectionID, CredentialID: p.CredentialID, Challenge: p.Challenge,
		RpID: p.RpID, PasskeyLabel: p.PasskeyLabel, UserVerification: p.UserVerification,
		KeyLabel: p.KeyLabel, KeyFingerprint: p.KeyFingerprint,
		resolveSign: p.ResolveSign, resolveKey: p.ResolveKey, reject: p.Reject,
	}
	s.mu.Lock()
	s.actions[a.ID] = a
	subs := append([]func(*Action){}, s.createdSubs...)
	s.mu.Unlock()
	for _, fn := range subs {
		fn(a)
	}
	return a
}

// Get returns an action snapshot pointer (nil when absent).
func (s *Store) Get(id string) *Action {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.actions[id]
}

// ResolveSign completes a webauthn-sign action with a browser assertion.
func (s *Store) ResolveSign(id string, resp signing.SignResponse) bool {
	a := s.takePending(id)
	if a == nil || a.Type != TypeWebAuthnSign {
		return false
	}
	a.Status = StatusCompleted
	if a.resolveSign != nil {
		a.resolveSign(resp)
	}
	s.emitResolved(a, OutcomeApproved, "")
	return true
}

// ResolveKey completes a key-approve action.
func (s *Store) ResolveKey(id string) bool {
	a := s.takePending(id)
	if a == nil || a.Type != TypeKeyApprove {
		return false
	}
	a.Status = StatusCompleted
	if a.resolveKey != nil {
		a.resolveKey()
	}
	s.emitResolved(a, OutcomeApproved, "")
	return true
}

// Deny rejects an action (the signer sees a sign failure -> tries next key).
func (s *Store) Deny(id string) bool {
	a := s.takePending(id)
	if a == nil {
		return false
	}
	a.Status = StatusDenied
	if a.reject != nil {
		a.reject(ErrDenied)
	}
	s.emitResolved(a, OutcomeDenied, "")
	return true
}

// CancelForConnection denies every pending action for a dead SSH connection
// (fix for #91: stranded prompts don't outlive the session). The reject
// closure is NOT called — the awaiter is already gone.
func (s *Store) CancelForConnection(connectionID, reason string) int {
	s.mu.Lock()
	var cancelled []*Action
	for _, a := range s.actions {
		if a.Status == StatusPending && a.ConnectionID == connectionID {
			a.Status = StatusDenied
			cancelled = append(cancelled, a)
		}
	}
	s.mu.Unlock()
	for _, a := range cancelled {
		s.emitResolved(a, OutcomeCancelled, reason)
	}
	return len(cancelled)
}

// Sweep expires overdue pending actions (janitor).
func (s *Store) Sweep() {
	now := s.clk.Now()
	s.mu.Lock()
	var expired []*Action
	for _, a := range s.actions {
		if a.Status == StatusPending && !a.ExpiresAt.After(now) {
			a.Status = StatusExpired
			expired = append(expired, a)
		}
	}
	s.mu.Unlock()
	for _, a := range expired {
		if a.reject != nil {
			a.reject(ErrExpired)
		}
		s.emitResolved(a, OutcomeExpired, "")
	}
}

func (s *Store) takePending(id string) *Action {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.actions[id]
	if !ok || a.Status != StatusPending {
		return nil
	}
	return a
}

func (s *Store) emitResolved(a *Action, outcome Outcome, cancelReason string) {
	s.mu.Lock()
	subs := append([]func(ResolvedEvent){}, s.resolvedSubs...)
	s.mu.Unlock()
	ev := ResolvedEvent{Action: a, Outcome: outcome, ResolvedAt: s.clk.Now(), CancelReason: cancelReason}
	for _, fn := range subs {
		fn(ev)
	}
}
