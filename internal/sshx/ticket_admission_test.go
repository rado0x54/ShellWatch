// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// One-time access tickets (#306) against a real SSH server: a guest
// session is admitted only through the normal endpoint-auth approval (here
// a file key's key-approve prompt), the prompt carries the ticket trigger,
// skipping it refuses the attempt, Ask again raises a fresh prompt, and an
// endpoint that accepts "none" authentication never admits anyone (#311).
package sshx

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/ticket"
)

// statusLog is a ticket.Publisher that records the guest's frames.
type statusLog struct {
	mu     sync.Mutex
	states []string
	opened string
}

func (s *statusLog) GuestStatus(_ string, st ticket.Status) {
	s.mu.Lock()
	s.states = append(s.states, st.State)
	s.mu.Unlock()
}
func (s *statusLog) GuestOpen(_, sessionID string) { s.mu.Lock(); s.opened = sessionID; s.mu.Unlock() }
func (s *statusLog) GuestClose(_ string, st ticket.Status) {
	s.mu.Lock()
	s.states = append(s.states, st.State)
	s.mu.Unlock()
}

func (s *statusLog) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.states) == 0 {
		return ""
	}
	return s.states[len(s.states)-1]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type ticketSSHRig struct {
	clk     *clock.Fake
	svc     *ticket.Service
	mgr     *terminal.Manager
	actions chan *approval.Action
	store   *approval.Store
	pub     *statusLog
}

func newTicketSSHRig(t *testing.T, port int) *ticketSSHRig {
	t.Helper()
	actionStore := approval.NewStore(clock.Real{}, newActionID())
	actions := make(chan *approval.Action, 16)
	actionStore.OnCreated(func(a *approval.Action) { actions <- a })
	p, _ := fileKeyParams(t, true, actionStore)
	p.HostKeys = newMemHostKeys()
	broker := approval.NewBroker(actionStore, func() string { return "https://sw.example" })
	p.BrokerFunc = func() SignBroker { return broker }
	p.NewConnectionID = newActionID()
	p.OnConnectionEnded = func(connID, reason string) { broker.CancelForConnection(connID, reason) }
	mgr := terminal.NewManager(NewPasskeyFactory(p), clock.Real{}, 0)
	ref := &terminal.EndpointRef{ID: "e1", Label: "Box", AccountID: "acc", Host: "127.0.0.1", Port: port,
		Username: "root", UserVerification: "required", AgentForward: true}
	n := 0
	clk := clock.NewFake(time.Now())
	resolve := func(_ context.Context, id, acc string) (*terminal.EndpointRef, error) {
		if id == "e1" && acc == "acc" {
			r := *ref
			return &r, nil
		}
		return nil, nil
	}
	svc := ticket.New(ticket.Params{
		Manager: mgr, Clock: clk, ResolveEndpoint: resolve,
		Open: func(ctx context.Context, acc, id string, tr terminal.Trigger) (*terminal.Session, error) {
			r, _ := resolve(ctx, id, acc)
			r.AgentForward = r.AgentForward && tr.Ticket.AgentForward
			return mgr.Create(ctx, *r, acc, tr)
		},
		NewID: func() string { n++; return "tkt-" + string(rune('0'+n)) },
	})
	pub := &statusLog{}
	svc.SetPublisher(pub)
	t.Cleanup(svc.Close)
	return &ticketSSHRig{clk: clk, svc: svc, mgr: mgr, actions: actions, store: actionStore, pub: pub}
}

func newActionID() func() string {
	var mu sync.Mutex
	n := 0
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		n++
		return "id-" + time.Now().Format("150405.000000") + "-" + string(rune('a'+n%26))
	}
}

func (r *ticketSSHRig) redeemAndAttach(t *testing.T) (guestID, code, cookie string) {
	t.Helper()
	minted, err := r.svc.Mint(context.Background(), ticket.MintParams{AccountID: "acc", EndpointID: "e1",
		Options: ticket.Options{Label: "Printer fix", ReasonRequired: true}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.svc.Redeem(context.Background(), ticket.RedeemParams{
		Token: minted.Token, Reason: "fix the printer", SourceIP: "203.0.113.7", UserAgent: "Kiosk/1",
	})
	if err != nil {
		t.Fatal(err)
	}
	guestID, ok := r.svc.GuestByCookie(res.Cookie)
	if !ok {
		t.Fatal("cookie does not resolve")
	}
	if err := r.svc.Attach(guestID); err != nil {
		t.Fatal(err)
	}
	return guestID, res.ConfirmationCode, res.Cookie
}

func (r *ticketSSHRig) nextAction(t *testing.T) *approval.Action {
	t.Helper()
	select {
	case a := <-r.actions:
		return a
	case <-time.After(10 * time.Second):
		t.Fatal("no approval prompt raised")
		return nil
	}
}

func TestTicketAdmittedThroughFileKeyApproval(t *testing.T) {
	_, port, _ := startEchoServer(t)
	r := newTicketSSHRig(t, port)
	guestID, code, _ := r.redeemAndAttach(t)

	// The prompt is the normal key-approve, with the ticket trigger.
	a := r.nextAction(t)
	if a.Type != approval.TypeKeyApprove || a.Context.Source != "endpoint-auth" {
		t.Fatalf("action %s / %s", a.Type, a.Context.Source)
	}
	raw, _ := json.Marshal(a.Context)
	var ctx struct {
		Trigger map[string]any `json:"trigger"`
	}
	_ = json.Unmarshal(raw, &ctx)
	for k, want := range map[string]any{
		"kind": "ticket", "reason": "fix the printer", "sourceIp": "203.0.113.7", "userAgent": "Kiosk/1",
		"confirmationCode": code, "ticketLabel": "Printer fix", "channel": "web",
		"agentForward": false, "lifetimeSeconds": float64(900),
	} {
		if ctx.Trigger[k] != want {
			t.Errorf("trigger.%s = %v, want %v (%s)", k, ctx.Trigger[k], want, raw)
		}
	}

	// Skip: the attempt fails, the guest session waits in refused.
	r.store.Deny(a.ID)
	waitFor(t, "refused", func() bool { return r.pub.last() == ticket.StateRefused })

	// Ask again (after the cooldown): a fresh prompt; approving it admits
	// the guest.
	r.clk.Advance(ticket.RetryCooldown)
	r.svc.Retry(guestID)
	a2 := r.nextAction(t)
	if a2.ID == a.ID || a2.Context.Ticket == nil || a2.Context.Ticket.ConfirmationCode != code {
		t.Fatalf("retry prompt %+v", a2.Context.Ticket)
	}
	r.store.ResolveKey(a2.ID)
	waitFor(t, "open", func() bool { return r.pub.last() == ticket.StateOpen })
	r.pub.mu.Lock()
	sid := r.pub.opened
	r.pub.mu.Unlock()
	sess := r.mgr.GetSession(sid)
	if sess == nil || sess.Source != terminal.SourceTicket || sess.Status != terminal.StatusOpen {
		t.Fatalf("admitted session %+v", sess)
	}
	waitFor(t, "shell output", func() bool {
		res, _ := r.mgr.ReadOutput(sid, 0, 100)
		return len(res.Data) > 0
	})

	// End: the terminal session goes with the guest session.
	r.svc.End(guestID)
	waitFor(t, "session closed", func() bool { return r.mgr.GetSession(sid) == nil })
}

// The admission window cancels an attempt whose prompt is still open — and
// with it the prompt itself.
func TestTicketAdmissionWindowCancelsOpenPrompt(t *testing.T) {
	_, port, _ := startEchoServer(t)
	r := newTicketSSHRig(t, port)
	_, _, cookie := r.redeemAndAttach(t)
	a := r.nextAction(t)
	// Revoke stands in for the window (same close path, no clock needed).
	views := r.svc.List("acc")
	if len(views) != 1 || r.svc.Revoke("acc", views[0].ID) != nil {
		t.Fatal("revoke failed")
	}
	waitFor(t, "prompt cancelled", func() bool {
		got := r.store.Get(a.ID)
		return got == nil || got.Status != approval.StatusPending
	})
	if _, ok := r.svc.GuestByCookie(cookie); ok {
		t.Error("guest still resolvable")
	}
}

// #311: an endpoint that lets anyone in without a key never admits a guest.
func TestTicketNoneAuthEndpointNeverAdmits(t *testing.T) {
	port, _, channels := startNoneAuthServer(t)
	r := newTicketSSHRig(t, port)
	r.redeemAndAttach(t)
	waitFor(t, "refused", func() bool { return r.pub.last() == ticket.StateRefused })
	if channels.Load() != 0 {
		t.Errorf("a channel was opened on a none-auth server")
	}
	if len(r.mgr.ListForAccount("acc")) != 0 {
		t.Error("a session is listed")
	}
	select {
	case a := <-r.actions:
		t.Errorf("a prompt was raised for a none-auth endpoint: %+v", a)
	default:
	}
}
