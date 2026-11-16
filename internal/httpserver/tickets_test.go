// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// One-time access tickets (#306) at the router level: mint/list/revoke,
// redemption (uniform 404, single use under concurrency, reason, capacity,
// the one-session 409), the guest WebSocket (Origin check, admission,
// refusal and Ask again, End vs disconnect, several tabs, isolation from the
// account hub), every deadline on a fake clock, and the audit trail. The
// SSH side is a gated factory: each attempt blocks until the test approves
// or refuses it, which is what the human's sign prompt does in production.
package httpserver

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/coder/websocket"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/ids"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/ticket"
	wshub "github.com/rado0x54/shellwatch/internal/ws"
)

// gatedFactory blocks every connect until the test decides it.
type gatedFactory struct {
	started   chan terminal.FactoryParams
	decisions chan error // nil approves
	mu        sync.Mutex
	last      *terminal.MockTransport
	cancelled int
}

func newGatedFactory() *gatedFactory {
	return &gatedFactory{started: make(chan terminal.FactoryParams, 32), decisions: make(chan error, 32)}
}

func (g *gatedFactory) factory(ctx context.Context, fp terminal.FactoryParams) (terminal.Transport, error) {
	g.started <- fp
	select {
	case err := <-g.decisions:
		if err != nil {
			return nil, err
		}
		tr := terminal.NewMockTransport()
		g.mu.Lock()
		g.last = tr
		g.mu.Unlock()
		return tr, nil
	case <-ctx.Done():
		g.mu.Lock()
		g.cancelled++
		g.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (g *gatedFactory) waitStarted(t *testing.T) terminal.FactoryParams {
	t.Helper()
	select {
	case fp := <-g.started:
		return fp
	case <-time.After(5 * time.Second):
		t.Fatal("no connect attempt started")
		return terminal.FactoryParams{}
	}
}

func (g *gatedFactory) noAttempt(t *testing.T) {
	t.Helper()
	select {
	case fp := <-g.started:
		t.Fatalf("unexpected connect attempt: %+v", fp.Trigger)
	case <-time.After(100 * time.Millisecond):
	}
}

func (g *gatedFactory) cancelledCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cancelled
}

type ticketRig struct {
	ts      *httptest.Server
	clk     *clock.Fake
	mgr     *terminal.Manager
	svc     *ticket.Service
	hub     *wshub.Hub
	gate    *gatedFactory
	db      *sql.DB
	maxSess int
	// demoID is a demo endpoint's id ("demo:…"), visible to every account.
	demoID string
	// lookupErr makes the redeem-time account check fail (a database
	// error), for the transient-failure path.
	lookupErr atomic.Bool
}

const guestOrigin = externalURL // "https://shellwatch.example"

func ticketServer(t *testing.T) *ticketRig {
	t.Helper()
	db, err := store.Open("sqlite:" + t.TempDir() + "/tickets.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO accounts (id,name,max_sessions,created_at,updated_at) VALUES ('acc-a','A',1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`,
		`INSERT INTO accounts (id,name,max_sessions,created_at,updated_at) VALUES ('acc-b','B',5,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`,
		`INSERT INTO endpoints (id,account_id,label,host,port,username,user_verification,agent_forward,enabled,created_at,updated_at) VALUES ('ep-a','acc-a','Secret Box','10.1.2.3',22,'root','required',1,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`,
		`INSERT INTO endpoints (id,account_id,label,host,port,username,user_verification,agent_forward,enabled,created_at,updated_at) VALUES ('ep-b','acc-b','Box B','127.0.0.1',22,'u','required',0,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	clk := clock.NewFake(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	gate := newGatedFactory()
	mgr := terminal.NewManager(gate.factory, clk, 0)
	hub := wshub.NewHub(mgr)
	t.Cleanup(hub.Close)
	epStore := store.NewEndpoints(db, clk)
	epSvc := &endpointsvc.Service{Endpoints: epStore, Demo: demo.NewService([]config.SeedEndpoint{{
		Label: "Demo", Parsed: config.EndpointAddress{Host: "demo.example", Port: 22, Username: "sw"},
	}})}
	rig := &ticketRig{clk: clk, mgr: mgr, hub: hub, gate: gate, db: db, maxSess: 1,
		demoID: epSvc.Demo.List("acc-a")[0].ID}
	accounts := store.NewAccounts(db)
	audit.NewWriter(db, clk).AttachManager(mgr, mgr.GetSession)
	ticketLog := audit.NewTicketEvents(db, clk)
	svc := ticket.New(ticket.Params{
		Manager: mgr, Clock: clk, Audit: ticketLog, Notifier: hub,
		ResolveEndpoint: epSvc.ActiveRefForAccount,
		AccountActive: func(ctx context.Context, id string) (bool, error) {
			if rig.lookupErr.Load() {
				return false, errors.New("database is locked")
			}
			a, err := accounts.Get(ctx, id)
			return err == nil && a != nil && a.Enabled, err
		},
		NewID: ids.NewUUID,
	})
	t.Cleanup(svc.Close)
	guestHub := wshub.NewGuestHub(wshub.GuestHubParams{Manager: mgr, Service: svc, ExternalURL: func() string { return externalURL }})
	t.Cleanup(guestHub.Close)
	svc.SetPublisher(guestHub)
	hub.SetGuestAttached(svc.GuestAttached)

	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	cfg.Security.AllowedNetworks = loopbackOnly
	principals := map[string]auth.Principal{
		"ui":   {AccountID: "acc-a", Scopes: []string{"ui"}},
		"ui-b": {AccountID: "acc-b", Scopes: []string{"ui"}},
	}
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		if p, ok := principals[tok]; ok {
			return &p
		}
		return nil
	})
	rig.svc = svc
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		WSHub:     hub,
		Endpoints: &rest.Endpoints{Svc: epSvc, Sessions: mgr, NewID: ids.NewUUID, OnDeleted: svc.CloseForEndpoint},
		Sessions: &rest.Sessions{Manager: mgr, Svc: epSvc, GuestAttached: svc.GuestAttached,
			MaxSessions: func(context.Context, string) (int, bool) { return rig.maxSess, true }},
		Audit:        &rest.Audit{Sessions: audit.NewSessions(db), Signings: audit.NewSignings(db), Tickets: ticketLog},
		Tickets:      &rest.Tickets{Service: svc},
		TicketRedeem: &rest.TicketRedeem{Service: svc, ExternalURL: func() string { return externalURL }},
		GuestHub:     guestHub,
	})
	rig.ts = httptest.NewServer(handler)
	t.Cleanup(rig.ts.Close)
	return rig
}

// ownerJSON calls an owner route with a bearer.
func (r *ticketRig) ownerJSON(t *testing.T, method, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, r.ts.URL+path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func (r *ticketRig) mint(t *testing.T, endpointID, body string) (id, token string) {
	t.Helper()
	st, out := r.ownerJSON(t, "POST", "/api/endpoints/"+endpointID+"/tickets", "ui", body)
	if st != 201 {
		t.Fatalf("mint: %d %v", st, out)
	}
	tk := out["ticket"].(map[string]any)
	return tk["id"].(string), out["token"].(string)
}

type redeemResult struct {
	status int
	body   map[string]any
	raw    string
	cookie string
	header http.Header
}

type redeemOpts struct {
	origin, cookie, bearer string
	noOrigin               bool
}

func (r *ticketRig) redeem(t *testing.T, token, reason string, o redeemOpts) redeemResult {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"token": token, "reason": reason})
	req, _ := http.NewRequest("POST", r.ts.URL+"/api/tickets/redeem", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GuestBrowser/1.0")
	if !o.noOrigin {
		origin := o.origin
		if origin == "" {
			origin = guestOrigin
		}
		req.Header.Set("Origin", origin)
	}
	if o.cookie != "" {
		req.AddCookie(&http.Cookie{Name: ticket.CookieName, Value: o.cookie})
	}
	if o.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+o.bearer)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	out := redeemResult{status: res.StatusCode, raw: strings.TrimSpace(string(b)), header: res.Header}
	_ = json.Unmarshal(b, &out.body)
	for _, c := range res.Cookies() {
		if c.Name == ticket.CookieName {
			out.cookie = c.Value
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
				t.Errorf("guest cookie attributes: %+v", c)
			}
		}
	}
	return out
}

func (r *ticketRig) dialGuest(t *testing.T, cookie, origin string) (*websocket.Conn, int) {
	t.Helper()
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	if cookie != "" {
		h.Set("Cookie", ticket.CookieName+"="+cookie)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, res, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(r.ts.URL, "http")+"/ws/guest", &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		if res != nil {
			return nil, res.StatusCode
		}
		t.Fatalf("dial guest: %v", err)
	}
	t.Cleanup(func() { c.CloseNow() })
	return c, http.StatusSwitchingProtocols
}

// readUntil reads guest frames until one matches.
func readUntil(t *testing.T, c *websocket.Conn, match func(map[string]any) bool) map[string]any {
	t.Helper()
	for i := 0; i < 50; i++ {
		msg := readMsg(t, c)
		if match(msg) {
			return msg
		}
	}
	t.Fatal("no matching frame")
	return nil
}

func statusIs(state string) func(map[string]any) bool {
	return func(m map[string]any) bool { return m["type"] == "status" && m["state"] == state }
}

func (r *ticketRig) sweep(d time.Duration) {
	r.clk.Advance(d)
	r.svc.Sweep()
}

// admit redeems a fresh ticket, attaches, approves, and returns the open
// guest connection plus the cookie and the session id.
func (r *ticketRig) admit(t *testing.T) (c *websocket.Conn, cookie, sessionID, ticketID string) {
	t.Helper()
	ticketID, token := r.mint(t, "ep-a", `{}`)
	res := r.redeem(t, token, "fix the printer", redeemOpts{})
	if res.status != 202 {
		t.Fatalf("redeem: %d %s", res.status, res.raw)
	}
	c, _ = r.dialGuest(t, res.cookie, guestOrigin)
	readUntil(t, c, statusIs("pending"))
	fp := r.gate.waitStarted(t)
	r.gate.decisions <- nil
	readUntil(t, c, statusIs("open"))
	return c, res.cookie, fp.SessionID, ticketID
}

func ticketEvents(t *testing.T, r *ticketRig, ticketID string) []string {
	t.Helper()
	page, err := audit.NewTicketEvents(r.db, nil).List(context.Background(), "acc-a", audit.TicketEventFilters{TicketID: ticketID, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(page.Rows) - 1; i >= 0; i-- {
		ev := page.Rows[i].Event
		if page.Rows[i].EndReason != nil && ev == "ended" {
			ev += ":" + *page.Rows[i].EndReason
		}
		out = append(out, ev)
	}
	return out
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// wantEvents waits for a ticket's audit trail to equal want.
func wantEvents(t *testing.T, r *ticketRig, ticketID string, want ...string) {
	t.Helper()
	var got []string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got = ticketEvents(t, r, ticketID); strings.Join(got, ",") == strings.Join(want, ",") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ticket events %v, want %v", got, want)
}

// --- mint -------------------------------------------------------------------

func TestTicketMintDefaultsAndBounds(t *testing.T) {
	r := ticketServer(t)
	st, out := r.ownerJSON(t, "POST", "/api/endpoints/ep-a/tickets", "ui", ``)
	if st != 201 {
		t.Fatalf("mint: %d %v", st, out)
	}
	tk := out["ticket"].(map[string]any)
	for k, want := range map[string]any{
		"redeemTtlSeconds": float64(300), "lifetimeSeconds": float64(900),
		"reasonRequired": true, "agentForward": false, "label": "", "state": "minted", "guest": nil,
	} {
		if tk[k] != want {
			t.Errorf("default %s = %v, want %v", k, tk[k], want)
		}
	}
	if tok, _ := out["token"].(string); len(tok) != 43 {
		t.Errorf("token %q: want 43 base64url chars (32 bytes)", tok)
	}
	for body, want := range map[string]int{
		`{"redeemTtlSeconds":59}`:    400,
		`{"redeemTtlSeconds":86401}`: 400,
		`{"lifetimeSeconds":59}`:     400,
		`{"lifetimeSeconds":28801}`:  400,
		// Would wrap past int64 nanoseconds to about 60 s if converted first.
		`{"redeemTtlSeconds":18446744134}`:             400,
		`{"lifetimeSeconds":18446744134}`:              400,
		`{"lifetimeSeconds":1e300}`:                    400,
		`{"lifetimeSeconds":"x"}`:                      400,
		`{"agentForward":"yes"}`:                       400,
		`{"redeemTtlSeconds":86400}`:                   201,
		`{"lifetimeSeconds":28800}`:                    201,
		`{"label":"Printer fix"}`:                      201,
		`{"redeemTtlSeconds":60.5}`:                    400,
		`{"reasonRequired":false}`:                     201,
		`{"agentForward":true,"x":1}`:                  201,
		`{"label":7}`:                                  400,
		`{"lifetimeSeconds":-1}`:                       400,
		`{"redeemTtlSeconds":0}`:                       400,
		`{"redeemTtlSeconds":null}`:                    201,
		`{"lifetimeSeconds":60}`:                       201,
		`{"redeemTtlSeconds":60}`:                      201,
		`{"label":"` + strings.Repeat("x", 300) + `"}`: 201,
	} {
		if st, out := r.ownerJSON(t, "POST", "/api/endpoints/ep-a/tickets", "ui", body); st != want {
			t.Errorf("mint %s: %d %v, want %d", body, st, out, want)
		}
	}
	// Foreign and unknown endpoints are indistinguishable.
	for _, ep := range []string{"ep-b", "nope"} {
		if st, _ := r.ownerJSON(t, "POST", "/api/endpoints/"+ep+"/tickets", "ui", `{}`); st != 404 {
			t.Errorf("mint on %s: %d, want 404", ep, st)
		}
	}
	// 20 outstanding -> the 21st is refused.
	for len(r.svc.List("acc-a")) < ticket.MaxOutstanding {
		r.mint(t, "ep-a", `{}`)
	}
	if st, out := r.ownerJSON(t, "POST", "/api/endpoints/ep-a/tickets", "ui", `{}`); st != 409 {
		t.Errorf("21st ticket: %d %v, want 409", st, out)
	}
	// Another account is unaffected, and sees none of acc-a's tickets.
	if st, out := r.ownerJSON(t, "GET", "/api/tickets", "ui-b", ""); st != 200 || len(out["tickets"].([]any)) != 0 {
		t.Errorf("acc-b list: %d %v", st, out)
	}
	if st, out := r.ownerJSON(t, "GET", "/api/tickets", "ui", ""); st != 200 || len(out["tickets"].([]any)) != 20 {
		t.Errorf("acc-a list: %d, %d tickets", st, len(out["tickets"].([]any)))
	}
	// Owner routes need the bearer; a guest cookie is worthless there.
	req, _ := http.NewRequest("GET", r.ts.URL+"/api/tickets", nil)
	req.AddCookie(&http.Cookie{Name: ticket.CookieName, Value: "anything"})
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != 401 {
		t.Errorf("cookie on owner route: %d, want 401", res.StatusCode)
	}
}

// --- redeem -----------------------------------------------------------------

func TestTicketRedeemUniform404(t *testing.T) {
	r := ticketServer(t)
	notFound := `{"error":"Not found"}`

	// Unknown.
	if res := r.redeem(t, "bogus", "x", redeemOpts{}); res.status != 404 || res.raw != notFound {
		t.Errorf("unknown: %d %s", res.status, res.raw)
	}
	// Used.
	_, used := r.mint(t, "ep-a", `{}`)
	if res := r.redeem(t, used, "x", redeemOpts{}); res.status != 202 {
		t.Fatalf("first redeem: %d %s", res.status, res.raw)
	}
	if res := r.redeem(t, used, "x", redeemOpts{}); res.status != 404 || res.raw != notFound {
		t.Errorf("used: %d %s", res.status, res.raw)
	}
	// Revoked.
	id, revoked := r.mint(t, "ep-a", `{}`)
	if st, _ := r.ownerJSON(t, "DELETE", "/api/tickets/"+id, "ui", ""); st != 200 {
		t.Fatalf("revoke: %d", st)
	}
	if res := r.redeem(t, revoked, "x", redeemOpts{}); res.status != 404 || res.raw != notFound {
		t.Errorf("revoked: %d %s", res.status, res.raw)
	}
	// Expired.
	_, expired := r.mint(t, "ep-a", `{"redeemTtlSeconds":60}`)
	r.clk.Advance(61 * time.Second)
	if res := r.redeem(t, expired, "x", redeemOpts{}); res.status != 404 || res.raw != notFound {
		t.Errorf("expired: %d %s", res.status, res.raw)
	}
	// Endpoint deleted after minting.
	_, gone := r.mint(t, "ep-a", `{}`)
	if _, err := r.db.Exec(`UPDATE endpoints SET enabled = 0 WHERE id = 'ep-a'`); err != nil {
		t.Fatal(err)
	}
	if res := r.redeem(t, gone, "x", redeemOpts{}); res.status != 404 || res.raw != notFound {
		t.Errorf("endpoint gone: %d %s", res.status, res.raw)
	}
	if _, err := r.db.Exec(`UPDATE endpoints SET enabled = 1 WHERE id = 'ep-a'`); err != nil {
		t.Fatal(err)
	}
	// Account disabled after minting.
	_, accGone := r.mint(t, "ep-a", `{}`)
	_, _ = r.db.Exec(`UPDATE accounts SET enabled = 0 WHERE id = 'acc-a'`)
	if res := r.redeem(t, accGone, "x", redeemOpts{}); res.status != 404 || res.raw != notFound {
		t.Errorf("account disabled: %d %s", res.status, res.raw)
	}
	_, _ = r.db.Exec(`UPDATE accounts SET enabled = 1 WHERE id = 'acc-a'`)
	// Every failure is Cache-Control: no-store and names nothing.
	res := r.redeem(t, "bogus", "x", redeemOpts{})
	if res.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", res.header.Get("Cache-Control"))
	}
}

func TestTicketConcurrentRedeemExactlyOneWins(t *testing.T) {
	r := ticketServer(t)
	_, token := r.mint(t, "ep-a", `{}`)
	const n = 16
	var wg sync.WaitGroup
	statuses := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- r.redeem(t, token, "x", redeemOpts{}).status
		}()
	}
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for s := range statuses {
		counts[s]++
	}
	if counts[202] != 1 || counts[404] != n-1 {
		t.Errorf("statuses %v, want one 202 and %d 404", counts, n-1)
	}
}

func TestTicketRedeemReason(t *testing.T) {
	r := ticketServer(t)
	_, token := r.mint(t, "ep-a", `{}`)
	// Required: an empty (or whitespace / control-only) reason is refused
	// and does not consume the ticket.
	for _, reason := range []string{"", "   ", "\n\t"} {
		if res := r.redeem(t, token, reason, redeemOpts{}); res.status != 400 {
			t.Errorf("reason %q: %d %s", reason, res.status, res.raw)
		}
	}
	res := r.redeem(t, token, "printer\x07 is down"+strings.Repeat("!", 400), redeemOpts{})
	if res.status != 202 {
		t.Fatalf("redeem: %d %s", res.status, res.raw)
	}
	views := r.svc.List("acc-a")
	got := views[0].Guest.Reason
	if strings.ContainsRune(got, 7) || len(got) > ticket.ReasonMaxLen || !strings.HasPrefix(got, "printer is down") {
		t.Errorf("sanitized reason = %q", got)
	}
	for _, k := range []string{"confirmationCode", "attachDeadline", "admissionWindowSeconds", "lifetimeSeconds", "agentForward"} {
		if _, ok := res.body[k]; !ok {
			t.Errorf("202 body lacks %s: %v", k, res.body)
		}
	}
	code := res.body["confirmationCode"].(string)
	if len(code) != 4 || strings.ContainsAny(code, "01OI") {
		t.Errorf("confirmation code %q", code)
	}
	// Optional: an empty reason is fine.
	_, optional := r.mint(t, "ep-a", `{"reasonRequired":false}`)
	if res := r.redeem(t, optional, "", redeemOpts{}); res.status != 202 {
		t.Errorf("optional reason: %d %s", res.status, res.raw)
	}
}

// Redeeming never connects; without an attach nothing is ever prompted, and
// the attach window releases the reservation. The ticket stays spent.
func TestTicketLostRedemptionResponse(t *testing.T) {
	r := ticketServer(t)
	id, token := r.mint(t, "ep-a", `{}`)
	if res := r.redeem(t, token, "x", redeemOpts{}); res.status != 202 {
		t.Fatalf("redeem: %d", res.status)
	}
	r.gate.noAttempt(t)
	r.sweep(29 * time.Second)
	if len(r.svc.List("acc-a")) != 1 {
		t.Fatal("guest session dropped before the attach window")
	}
	r.sweep(2 * time.Second)
	if n := len(r.svc.List("acc-a")); n != 0 {
		t.Fatalf("%d tickets live after the attach window", n)
	}
	r.gate.noAttempt(t)
	if res := r.redeem(t, token, "x", redeemOpts{}); res.status != 404 {
		t.Errorf("spent ticket: %d", res.status)
	}
	wantEvents(t, r, id, "minted", "redeemed", "ended:ticket-unattached")
}

// --- admission ---------------------------------------------------------------

func TestTicketAdmissionEndToEnd(t *testing.T) {
	r := ticketServer(t)
	ticketID, token := r.mint(t, "ep-a", `{"label":"Printer fix"}`)
	res := r.redeem(t, token, "fix the printer", redeemOpts{})
	if res.status != 202 {
		t.Fatalf("redeem: %d %s", res.status, res.raw)
	}
	code := res.body["confirmationCode"].(string)
	// No prompt before the guest can see the code.
	r.gate.noAttempt(t)

	c, _ := r.dialGuest(t, res.cookie, guestOrigin)
	pending := readUntil(t, c, statusIs("pending"))
	if pending["code"] != code || pending["admissionDeadline"] == nil {
		t.Errorf("pending frame %v (code %s)", pending, code)
	}
	fp := r.gate.waitStarted(t)
	tr := fp.Trigger
	if tr.Kind != terminal.SourceTicket || tr.Reason != "fix the printer" || tr.SourceIP != "127.0.0.1" ||
		tr.Ticket == nil || tr.Ticket.ConfirmationCode != code || tr.Ticket.Label != "Printer fix" ||
		tr.Ticket.Channel != terminal.TicketChannelWeb || tr.Ticket.UserAgent != "GuestBrowser/1.0" ||
		tr.Ticket.TicketID != ticketID || tr.Ticket.LifetimeSeconds != 900 || tr.Ticket.AgentForward {
		t.Errorf("trigger %+v ticket %+v", tr, tr.Ticket)
	}
	// Agent forwarding off by default, whatever the endpoint says.
	if fp.Endpoint.AgentForward {
		t.Error("agent forwarding reached the backend with the ticket option off")
	}
	// The owner sees the attempt while it waits.
	_, list := r.ownerJSON(t, "GET", "/api/tickets", "ui", "")
	tk := list["tickets"].([]any)[0].(map[string]any)
	if tk["state"] != "pending" || tk["guest"].(map[string]any)["attached"] != true {
		t.Errorf("owner view while pending: %v", tk)
	}

	r.gate.decisions <- nil
	open := readUntil(t, c, statusIs("open"))
	if open["lifetimeDeadline"] == nil {
		t.Errorf("open frame %v", open)
	}
	// Input reaches the session; output comes back as guest output frames.
	writeMsg(t, c, map[string]any{"type": "input", "data": "hello"})
	out := readUntil(t, c, func(m map[string]any) bool { return m["type"] == "output" && m["data"] != "" })
	if out["data"] != "hello" || out["sessionId"] != nil {
		t.Errorf("output frame %v", out)
	}
	writeMsg(t, c, map[string]any{"type": "resize", "cols": 120, "rows": 40})

	// The owner's session list: source ticket, ticket fields, attached.
	_, sessions := r.ownerJSON(t, "GET", "/api/sessions", "ui", "")
	s := sessions["sessions"].([]any)[0].(map[string]any)
	if s["source"] != "ticket" || s["ticketId"] != ticketID || s["ticketLabel"] != "Printer fix" ||
		s["guestAttached"] != true || s["reason"] != "fix the printer" {
		t.Errorf("owner session DTO %v", s)
	}

	// End closes immediately and for good.
	writeMsg(t, c, map[string]any{"type": "end"})
	closed := readUntil(t, c, statusIs("closed"))
	if closed["message"] != ticket.MsgEnded {
		t.Errorf("closed frame %v", closed)
	}
	eventually(t, "terminal session closed", func() bool { return r.mgr.GetSession(fp.SessionID) == nil })
	if _, st := r.dialGuest(t, res.cookie, guestOrigin); st != 404 {
		t.Errorf("cookie after End: %d, want 404", st)
	}
	wantEvents(t, r, ticketID, "minted", "redeemed", "attached", "admitted", "ended:client.guest")
	// The lifecycle row carries the ticket.
	var src, tid, reason, closeReason string
	eventually(t, "lifecycle close", func() bool {
		err := r.db.QueryRow(`SELECT source, ticket_id, reason, COALESCE(close_reason,'') FROM audit_session_lifecycle WHERE session_id = ?`, fp.SessionID).
			Scan(&src, &tid, &reason, &closeReason)
		return err == nil && closeReason != ""
	})
	if src != "ticket" || tid != ticketID || reason != "fix the printer" || closeReason != "client.guest" {
		t.Errorf("lifecycle row: %s %s %s %s", src, tid, reason, closeReason)
	}
}

func TestTicketAgentForwardFollowsEndpointWhenEnabled(t *testing.T) {
	r := ticketServer(t)
	_, token := r.mint(t, "ep-a", `{"agentForward":true}`)
	res := r.redeem(t, token, "x", redeemOpts{})
	r.dialGuest(t, res.cookie, guestOrigin)
	fp := r.gate.waitStarted(t)
	if !fp.Endpoint.AgentForward || !fp.Trigger.Ticket.AgentForward {
		t.Errorf("agent forwarding on + endpoint on: %v / %v", fp.Endpoint.AgentForward, fp.Trigger.Ticket.AgentForward)
	}
}

func TestTicketRefusedAskAgainAndAdmissionWindow(t *testing.T) {
	r := ticketServer(t)
	ticketID, token := r.mint(t, "ep-a", `{}`)
	res := r.redeem(t, token, "x", redeemOpts{})
	c, _ := r.dialGuest(t, res.cookie, guestOrigin)
	first := readUntil(t, c, statusIs("pending"))
	fp1 := r.gate.waitStarted(t)

	// retry while pending is ignored.
	writeMsg(t, c, map[string]any{"type": "retry"})
	r.gate.noAttempt(t)

	// Every key skipped: the attempt fails, the guest session survives.
	r.gate.decisions <- errors.New("All configured authentication methods failed (endpoint 10.1.2.3 root)")
	refused := readUntil(t, c, statusIs("refused"))
	if refused["message"] != ticket.MsgNotGranted || refused["remainingSeconds"] == nil || refused["code"] != first["code"] {
		t.Errorf("refused frame %v", refused)
	}
	raw, _ := json.Marshal(refused)
	for _, leak := range []string{"10.1.2.3", "root", "Secret Box", "authentication"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("refused frame leaks %q: %s", leak, raw)
		}
	}
	// Nothing retries by itself.
	r.gate.noAttempt(t)
	// Still counted once against the cap, cookie still valid.
	if n := len(r.svc.List("acc-a")); n != 1 {
		t.Errorf("%d live tickets after refusal", n)
	}

	// Ask again: a fresh attempt with the same code and reason.
	r.clk.Advance(time.Minute)
	writeMsg(t, c, map[string]any{"type": "retry"})
	readUntil(t, c, statusIs("pending"))
	fp2 := r.gate.waitStarted(t)
	if fp2.SessionID == fp1.SessionID || fp2.Trigger.Ticket.ConfirmationCode != fp1.Trigger.Ticket.ConfirmationCode ||
		fp2.Trigger.Reason != fp1.Trigger.Reason {
		t.Errorf("retry attempt %+v vs first %+v", fp2, fp1)
	}
	// The admission window (5 min from the first attach) is not extended by
	// the retry: it ends this attempt while its prompt is still open.
	r.sweep(4*time.Minute - time.Second)
	if n := len(r.svc.List("acc-a")); n != 1 {
		t.Fatal("closed before the admission window")
	}
	r.sweep(2 * time.Second)
	closed := readUntil(t, c, statusIs("closed"))
	if closed["message"] != ticket.MsgNotGranted {
		t.Errorf("closed frame %v", closed)
	}
	eventually(t, "attempt cancelled", func() bool { return r.gate.cancelledCount() == 1 })
	wantEvents(t, r, ticketID, "minted", "redeemed", "attached", "attempt-failed", "retried", "ended:ticket-not-admitted")
}

func TestTicketAdmissionWindowClosesFromRefused(t *testing.T) {
	r := ticketServer(t)
	_, token := r.mint(t, "ep-a", `{}`)
	res := r.redeem(t, token, "x", redeemOpts{})
	c, _ := r.dialGuest(t, res.cookie, guestOrigin)
	r.gate.waitStarted(t)
	r.gate.decisions <- errors.New("skipped")
	readUntil(t, c, statusIs("refused"))
	r.sweep(5 * time.Minute)
	readUntil(t, c, statusIs("closed"))
	// retry after the window changes nothing.
	r.gate.noAttempt(t)
}

func TestTicketRevokeInEveryState(t *testing.T) {
	r := ticketServer(t)
	// minted
	id, _ := r.mint(t, "ep-a", `{}`)
	if st, _ := r.ownerJSON(t, "DELETE", "/api/tickets/"+id, "ui", ""); st != 200 {
		t.Errorf("revoke minted: %d", st)
	}
	// pending (prompt open): revoke cancels the attempt.
	id, token := r.mint(t, "ep-a", `{}`)
	res := r.redeem(t, token, "x", redeemOpts{})
	c, _ := r.dialGuest(t, res.cookie, guestOrigin)
	r.gate.waitStarted(t)
	if st, _ := r.ownerJSON(t, "DELETE", "/api/tickets/"+id, "ui-b", ""); st != 404 {
		t.Errorf("foreign revoke: %d", st)
	}
	if st, _ := r.ownerJSON(t, "DELETE", "/api/tickets/"+id, "ui", ""); st != 200 {
		t.Errorf("revoke pending: %d", st)
	}
	readUntil(t, c, statusIs("closed"))
	eventually(t, "attempt cancelled", func() bool { return r.gate.cancelledCount() == 1 })
	// open: revoke closes the terminal session.
	c, _, sid, id := r.admit(t)
	if st, _ := r.ownerJSON(t, "DELETE", "/api/tickets/"+id, "ui", ""); st != 200 {
		t.Errorf("revoke open: %d", st)
	}
	readUntil(t, c, statusIs("closed"))
	eventually(t, "session closed", func() bool { return r.mgr.GetSession(sid) == nil })
	if st, _ := r.ownerJSON(t, "DELETE", "/api/tickets/"+id, "ui", ""); st != 404 {
		t.Errorf("revoke twice: %d", st)
	}
}

// The owner kills the guest's session from the normal session list: the
// guest session goes with it.
func TestTicketOwnerKillClosesGuest(t *testing.T) {
	r := ticketServer(t)
	c, cookie, sid, _ := r.admit(t)
	if st, _ := r.ownerJSON(t, "DELETE", "/api/sessions/"+sid, "ui", ""); st != 200 {
		t.Fatalf("kill: %d", st)
	}
	readUntil(t, c, statusIs("closed"))
	if _, st := r.dialGuest(t, cookie, guestOrigin); st != 404 {
		t.Errorf("cookie after kill: %d", st)
	}
}

// Output the remote side emits right before hanging up (a logout message, a
// last command's result) reaches the guest before the final closed status.
func TestTicketGuestGetsTailOutputBeforeClose(t *testing.T) {
	r := ticketServer(t)
	c, _, _, _ := r.admit(t)
	r.gate.mu.Lock()
	tr := r.gate.last
	r.gate.mu.Unlock()
	tr.Push([]byte("logout\r\n"))
	_ = tr.Close()
	var out strings.Builder
	readUntil(t, c, func(m map[string]any) bool {
		if m["type"] == "output" {
			out.WriteString(m["data"].(string))
		}
		return m["type"] == "status" && m["state"] == "closed"
	})
	if !strings.Contains(out.String(), "logout") {
		t.Errorf("guest missed the tail output: %q", out.String())
	}
}

// Every guest status frame carries the server's clock, so the page can
// count deadlines down without trusting the guest device's clock.
func TestTicketStatusCarriesServerTime(t *testing.T) {
	r := ticketServer(t)
	_, token := r.mint(t, "ep-a", `{}`)
	res := r.redeem(t, token, "x", redeemOpts{})
	r.clk.Advance(7 * time.Second)
	c, _ := r.dialGuest(t, res.cookie, guestOrigin)
	st := readUntil(t, c, statusIs("pending"))
	if want := r.clk.Now().UTC().Format(clock.ISOMillis); st["serverTime"] != want {
		t.Errorf("serverTime = %v, want %s", st["serverTime"], want)
	}
}

func TestTicketSessionLifetime(t *testing.T) {
	r := ticketServer(t)
	_, token := r.mint(t, "ep-a", `{"lifetimeSeconds":60}`)
	res := r.redeem(t, token, "x", redeemOpts{})
	r.clk.Advance(20 * time.Second) // before admission: not counted
	c, _ := r.dialGuest(t, res.cookie, guestOrigin)
	fp := r.gate.waitStarted(t)
	r.clk.Advance(2 * time.Minute)
	r.gate.decisions <- nil
	readUntil(t, c, statusIs("open"))
	r.sweep(59 * time.Second)
	if r.mgr.GetSession(fp.SessionID) == nil {
		t.Fatal("closed before the lifetime")
	}
	r.sweep(2 * time.Second)
	readUntil(t, c, statusIs("closed"))
	eventually(t, "session closed", func() bool { return r.mgr.GetSession(fp.SessionID) == nil })
}

// --- connections --------------------------------------------------------------

func TestTicketTabsAndReconnectGrace(t *testing.T) {
	r := ticketServer(t)
	c1, cookie, sid, ticketID := r.admit(t)
	// A second tab of the same browser attaches and sees the same output.
	c2, _ := r.dialGuest(t, cookie, guestOrigin)
	readUntil(t, c2, statusIs("open"))
	writeMsg(t, c2, map[string]any{"type": "input", "data": "from-tab-2"})
	for _, c := range []*websocket.Conn{c1, c2} {
		readUntil(t, c, func(m map[string]any) bool {
			return m["type"] == "output" && strings.Contains(m["data"].(string), "from-tab-2")
		})
	}
	// Closing one tab does not start the grace.
	c1.Close(websocket.StatusNormalClosure, "")
	eventually(t, "one connection left", func() bool {
		v := r.svc.List("acc-a")
		return len(v) == 1 && v[0].Guest.Connections == 1
	})
	r.sweep(2 * time.Minute)
	if r.mgr.GetSession(sid) == nil {
		t.Fatal("closed while a tab was still attached")
	}
	// Closing the last one does.
	c2.Close(websocket.StatusNormalClosure, "")
	eventually(t, "detached", func() bool {
		attached, ok := r.svc.GuestAttached(sid)
		return ok && !attached
	})
	_, sessions := r.ownerJSON(t, "GET", "/api/sessions", "ui", "")
	if s := sessions["sessions"].([]any)[0].(map[string]any); s["guestAttached"] != false {
		t.Errorf("owner sees guestAttached %v", s["guestAttached"])
	}
	// Reattach inside the grace: output caught up (reset + full buffer).
	r.clk.Advance(30 * time.Second)
	c3, _ := r.dialGuest(t, cookie, guestOrigin)
	readUntil(t, c3, statusIs("open"))
	catchUp := readUntil(t, c3, func(m map[string]any) bool { return m["type"] == "output" })
	if catchUp["reset"] != true || !strings.Contains(catchUp["data"].(string), "from-tab-2") {
		t.Errorf("catch-up frame %v", catchUp)
	}
	c3.Close(websocket.StatusNormalClosure, "")
	eventually(t, "detached again", func() bool { a, ok := r.svc.GuestAttached(sid); return ok && !a })
	r.sweep(59 * time.Second)
	if r.mgr.GetSession(sid) == nil {
		t.Fatal("closed before the grace ran out")
	}
	r.sweep(2 * time.Second)
	eventually(t, "session closed", func() bool { return r.mgr.GetSession(sid) == nil })
	want := "ended:guest-disconnected"
	eventually(t, "end reason", func() bool {
		ev := ticketEvents(t, r, ticketID)
		return len(ev) > 0 && ev[len(ev)-1] == want
	})
}

func TestTicketGuestConnectionCap(t *testing.T) {
	r := ticketServer(t)
	_, cookie, _, _ := r.admit(t)
	for i := 1; i < ticket.MaxConnections; i++ {
		c, _ := r.dialGuest(t, cookie, guestOrigin)
		readUntil(t, c, statusIs("open"))
	}
	c, _ := r.dialGuest(t, cookie, guestOrigin)
	msg := readUntil(t, c, statusIs("closed"))
	if msg["message"] == "" {
		t.Errorf("cap frame %v", msg)
	}
	if v := r.svc.List("acc-a"); v[0].Guest.Connections != ticket.MaxConnections || v[0].State != "open" {
		t.Errorf("after the refused attach: %+v", v[0].Guest)
	}
}

// Guest connections are never in the account hub's set: account-level
// frames never reach them, and every other message type is dropped.
func TestTicketGuestIsolation(t *testing.T) {
	r := ticketServer(t)
	c, _, _, _ := r.admit(t)
	// An owner UI session of the same account, with output.
	rig := r
	owner := dialOwnerWS(t, rig.ts, "ui")
	readMsg(t, owner) // connect-time sessions:changed
	r.hub.SendToAccount("acc-a", map[string]any{"type": "sign:request", "id": "secret"})
	writeMsg(t, c, map[string]any{"type": "terminal:attach", "sessionId": "sess_000000000000"})
	writeMsg(t, c, map[string]any{"type": "terminal:close", "sessionId": "sess_000000000000"})
	writeMsg(t, c, map[string]any{"type": "input", "data": "marker"})
	for {
		msg := readMsg(t, c)
		if msg["type"] != "status" && msg["type"] != "output" {
			t.Fatalf("guest received %v", msg)
		}
		if msg["type"] == "output" && strings.Contains(msg["data"].(string), "marker") {
			break
		}
	}
}

func dialOwnerWS(t *testing.T, ts *httptest.Server, token string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/ws",
		&websocket.DialOptions{Subprotocols: []string{auth.WSBearerSubprotocol, token}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	return c
}

// --- capacity ---------------------------------------------------------------

func TestTicketGuestCapacity(t *testing.T) {
	r := ticketServer(t)
	var tokens []string
	for i := 0; i < 5; i++ {
		_, tok := r.mint(t, "ep-a", `{}`)
		tokens = append(tokens, tok)
	}
	var wg sync.WaitGroup
	results := make([]redeemResult, len(tokens))
	for i, tok := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = r.redeem(t, tok, "x", redeemOpts{})
		}()
	}
	wg.Wait()
	var ok, full []int
	for i, res := range results {
		switch res.status {
		case 202:
			ok = append(ok, i)
		case 429:
			full = append(full, i)
			if res.header.Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
		default:
			t.Errorf("redeem %d: %d %s", i, res.status, res.raw)
		}
	}
	if len(ok) != ticket.MaxGuestSessions || len(full) != 2 {
		t.Fatalf("202s %v, 429s %v", ok, full)
	}
	// Guest sessions don't use up UI capacity (max_sessions 1 here): admit
	// one guest, then open a UI session.
	c, _ := r.dialGuest(t, results[ok[0]].cookie, guestOrigin)
	r.gate.waitStarted(t)
	r.gate.decisions <- nil
	readUntil(t, c, statusIs("open"))
	if n := r.mgr.CountOpenForAccount("acc-a"); n != 0 {
		t.Errorf("CountOpenForAccount counts guest sessions: %d", n)
	}
	r.gate.decisions <- nil
	if st, out := r.ownerJSON(t, "POST", "/api/sessions", "ui", `{"endpointId":"ep-a"}`); st != 200 {
		t.Errorf("UI session next to a guest session: %d %v", st, out)
	}
	<-r.gate.started
	// Ending a guest session frees a slot; the 429'd ticket was not consumed.
	writeMsg(t, c, map[string]any{"type": "end"})
	readUntil(t, c, statusIs("closed"))
	if res := r.redeem(t, tokens[full[0]], "x", redeemOpts{}); res.status != 202 {
		t.Errorf("429'd ticket after a slot freed: %d %s", res.status, res.raw)
	}
}

// --- browser rules ------------------------------------------------------------

func TestTicketOneGuestSessionPerBrowser(t *testing.T) {
	r := ticketServer(t)
	_, first := r.mint(t, "ep-a", `{}`)
	_, second := r.mint(t, "ep-a", `{}`)
	res := r.redeem(t, first, "x", redeemOpts{})
	if again := r.redeem(t, second, "x", redeemOpts{cookie: res.cookie}); again.status != 409 {
		t.Fatalf("second redeem in the same browser: %d %s", again.status, again.raw)
	}
	// Not consumed: another browser can still redeem it.
	if other := r.redeem(t, second, "x", redeemOpts{}); other.status != 202 {
		t.Errorf("second ticket after the 409: %d", other.status)
	}
}

func TestTicketOriginMatrix(t *testing.T) {
	r := ticketServer(t)
	_, token := r.mint(t, "ep-a", `{}`)
	bad := []redeemOpts{
		{origin: "https://demo.shellwatch.example"}, // sibling subdomain
		{origin: "https://evil.example"},
		{origin: "null"},
		{noOrigin: true},
		{origin: "http://shellwatch.example"}, // scheme
	}
	for _, o := range bad {
		if res := r.redeem(t, token, "x", o); res.status != 403 || res.cookie != "" {
			t.Errorf("redeem with origin %+v: %d (cookie %v)", o, res.status, res.cookie != "")
		}
	}
	// Default port in the Origin is normalized; the Host httptest sees
	// (127.0.0.1:port, no TLS) differs from externalUrl, as behind a proxy.
	res := r.redeem(t, token, "x", redeemOpts{origin: "https://shellwatch.example:443"})
	if res.status != 202 {
		t.Fatalf("redeem with correct origin: %d %s", res.status, res.raw)
	}
	for _, origin := range []string{"https://demo.shellwatch.example", "https://evil.example", "null", ""} {
		if _, st := r.dialGuest(t, res.cookie, origin); st != 403 {
			t.Errorf("guest WS with origin %q: %d, want 403", origin, st)
		}
	}
	r.gate.noAttempt(t) // none of the refused handshakes attached
	if _, st := r.dialGuest(t, res.cookie, guestOrigin); st != 101 {
		t.Errorf("guest WS with the right origin: %d", st)
	}
}

// Guest routes behave identically with no bearer, a valid bearer, or an
// invalid one.
func TestTicketGuestRoutesIgnoreBearer(t *testing.T) {
	r := ticketServer(t)
	for _, bearer := range []string{"", "ui", "ui-b", "garbage"} {
		if res := r.redeem(t, "bogus", "x", redeemOpts{bearer: bearer}); res.status != 404 || res.raw != `{"error":"Not found"}` {
			t.Errorf("bearer %q, bogus ticket: %d %s", bearer, res.status, res.raw)
		}
		_, token := r.mint(t, "ep-a", `{}`)
		res := r.redeem(t, token, "x", redeemOpts{bearer: bearer})
		if res.status != 202 {
			t.Errorf("bearer %q: %d %s", bearer, res.status, res.raw)
			continue
		}
		h := http.Header{"Origin": {guestOrigin}, "Cookie": {ticket.CookieName + "=" + res.cookie}}
		if bearer != "" {
			h.Set("Authorization", "Bearer "+bearer)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(r.ts.URL, "http")+"/ws/guest", &websocket.DialOptions{HTTPHeader: h})
		cancel()
		if err != nil {
			t.Errorf("bearer %q: guest WS: %v", bearer, err)
			continue
		}
		readUntil(t, c, statusIs("pending"))
		r.gate.waitStarted(t)
		writeMsg(t, c, map[string]any{"type": "end"})
		readUntil(t, c, statusIs("closed"))
		c.CloseNow()
	}
	// The guest cookie means nothing to /ws and /api/*.
	_, token := r.mint(t, "ep-a", `{}`)
	res := r.redeem(t, token, "x", redeemOpts{})
	req, _ := http.NewRequest("GET", r.ts.URL+"/api/sessions", nil)
	req.AddCookie(&http.Cookie{Name: ticket.CookieName, Value: res.cookie})
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Errorf("guest cookie on /api/sessions: %d", resp.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(r.ts.URL, "http")+"/ws",
		&websocket.DialOptions{HTTPHeader: http.Header{"Cookie": {ticket.CookieName + "=" + res.cookie}}})
	if err == nil || resp == nil || resp.StatusCode != 401 {
		t.Errorf("guest cookie on /ws: %v %v", err, resp)
	}
}

func TestTicketEndpointDeletedEndsGuest(t *testing.T) {
	r := ticketServer(t)
	_, token := r.mint(t, "ep-a", `{}`)
	minted, _ := r.mint(t, "ep-a", `{}`)
	res := r.redeem(t, token, "x", redeemOpts{})
	c, _ := r.dialGuest(t, res.cookie, guestOrigin)
	r.gate.waitStarted(t)
	r.gate.decisions <- errors.New("skipped")
	readUntil(t, c, statusIs("refused"))
	if st, out := r.ownerJSON(t, "DELETE", "/api/endpoints/ep-a", "ui", ""); st != 200 {
		t.Fatalf("delete endpoint: %d %v", st, out)
	}
	readUntil(t, c, statusIs("closed"))
	for _, v := range r.svc.List("acc-a") {
		if v.ID == minted {
			t.Error("minted ticket survived its endpoint")
		}
	}
}

// --- goldens ----------------------------------------------------------------

func TestTicketGoldens(t *testing.T) {
	r := ticketServer(t)
	st, minted := r.ownerJSON(t, "POST", "/api/endpoints/ep-a/tickets", "ui", `{"label":"Printer fix"}`)
	assertBodyGolden(t, "ticket-mint", st, minted)
	id := minted["ticket"].(map[string]any)["id"].(string)
	token := minted["token"].(string)

	r.clk.Advance(time.Second)
	res := r.redeem(t, token, "fix the printer", redeemOpts{})
	assertBodyGolden(t, "ticket-redeem", res.status, res.body)
	again := r.redeem(t, token, "x", redeemOpts{})
	assertBodyGolden(t, "ticket-redeem-not-found", again.status, again.body)

	st, list := r.ownerJSON(t, "GET", "/api/tickets", "ui", "")
	assertBodyGolden(t, "ticket-list", st, list)

	st, revoked := r.ownerJSON(t, "DELETE", "/api/tickets/"+id, "ui", "")
	assertBodyGolden(t, "ticket-revoke", st, revoked)

	// The audit page of a ticket revoked before redemption: one row per
	// event, each at its own timestamp, so the order is deterministic.
	r.clk.Advance(time.Second)
	other, _ := r.mint(t, "ep-a", `{"label":"Spare"}`)
	r.clk.Advance(time.Second)
	if st, _ := r.ownerJSON(t, "DELETE", "/api/tickets/"+other, "ui", ""); st != 200 {
		t.Fatalf("revoke: %d", st)
	}
	st, page := r.ownerJSON(t, "GET", "/api/audit/tickets?ticketId="+other, "ui", "")
	assertBodyGolden(t, "audit-tickets", st, page)
	st, inv := r.ownerJSON(t, "GET", "/api/audit/tickets?event=bogus", "ui", "")
	assertBodyGolden(t, "audit-tickets-invalid-event", st, inv)
}

// Neither the ticket token nor the guest cookie ever reaches the log.
func TestTicketSecretsNeverLogged(t *testing.T) {
	var buf strings.Builder
	var mu sync.Mutex
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}), &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	r := ticketServer(t)
	_, token := r.mint(t, "ep-a", `{}`)
	res := r.redeem(t, token, "x", redeemOpts{})
	c, _ := r.dialGuest(t, res.cookie, guestOrigin)
	r.gate.waitStarted(t)
	writeMsg(t, c, map[string]any{"type": "end"})
	readUntil(t, c, statusIs("closed"))
	r.redeem(t, token, "x", redeemOpts{origin: "https://evil.example"})
	mu.Lock()
	logged := buf.String()
	mu.Unlock()
	for name, secret := range map[string]string{"token": token, "cookie": res.cookie} {
		if strings.Contains(logged, secret) {
			t.Errorf("%s leaked into the log", name)
		}
	}
	for _, want := range []string{"ticket: minted", "ticket: redeemed", "ticket: attached", "ticket: ended", "ws: guest origin rejected"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log lacks %q", want)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// /t (and /t/) is served with a strict CSP (scripts from this origin plus the inline
// bootstrap by hash, no workers) and is never cached.
func TestGuestPageCSP(t *testing.T) {
	index := `<html><head><script src="/config.js"></script></head><body><script>start()</script></body></html>`
	fs := fstest.MapFS{"index.html": {Data: []byte(index)}}
	h := spaHandler(fs, func() string { return "https://sw.example.com" })
	for _, path := range []string{"/t", "/t/"} {
		t.Run(path, func(t *testing.T) {
			checkGuestPageHeaders(t, h, path)
		})
	}
	// Other SPA routes keep the default headers.
	for _, path := range []string{"/settings", "/t/x", "/tx"} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest("GET", path, nil))
		if rec.Header().Get("Content-Security-Policy") != "" {
			t.Errorf("%s got the guest CSP", path)
		}
	}
}

func checkGuestPageHeaders(t *testing.T, h http.HandlerFunc, path string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", path, nil))
	csp := rec.Header().Get("Content-Security-Policy")
	sum := sha256.Sum256([]byte("start()"))
	for _, want := range []string{
		"script-src 'self' 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'",
		"connect-src 'self' wss://sw.example.com", "worker-src 'none'", "frame-ancestors 'none'",
		"object-src 'none'", "base-uri 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	scriptSrc := strings.SplitN(strings.SplitN(csp, "script-src", 2)[1], ";", 2)[0]
	if strings.Contains(scriptSrc, "unsafe") {
		t.Errorf("script-src allows unsafe sources: %s", scriptSrc)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", rec.Header().Get("Cache-Control"))
	}
}

// The gate exemption is method-exact: only POST /api/tickets/redeem and
// GET /ws/guest skip the bearer gate.
func TestTicketGateExemptionIsMethodExact(t *testing.T) {
	r := ticketServer(t)
	for _, m := range []string{"GET", "DELETE", "PUT"} {
		if st, _ := r.ownerJSON(t, m, "/api/tickets/redeem", "", ""); st != 401 {
			t.Errorf("%s /api/tickets/redeem without bearer: %d, want 401", m, st)
		}
	}
}

// A demo endpoint's id contains ":", which the client sends percent-encoded
// (encodeURIComponent): minting must decode it.
func TestTicketMintForDemoEndpoint(t *testing.T) {
	r := ticketServer(t)
	escaped := strings.ReplaceAll(r.demoID, ":", "%3A")
	st, out := r.ownerJSON(t, "POST", "/api/endpoints/"+escaped+"/tickets", "ui", ``)
	if st != 201 {
		t.Fatalf("mint for %s: %d %v", escaped, st, out)
	}
	if got := out["ticket"].(map[string]any)["endpointId"]; got != r.demoID {
		t.Errorf("endpointId = %v, want %s", got, r.demoID)
	}
	tk := out["ticket"].(map[string]any)["id"].(string)
	if st, _ := r.ownerJSON(t, "DELETE", "/api/tickets/"+tk, "ui", ""); st != 200 {
		t.Errorf("revoke: %d", st)
	}
}

// A failed eligibility lookup during redeem (database error, cancelled
// request) answers 503 and leaves the ticket redeemable; only a definite
// "account/endpoint gone" spends it.
func TestTicketRedeemTransientLookupFailureKeepsTicket(t *testing.T) {
	r := ticketServer(t)
	_, out := r.ownerJSON(t, "POST", "/api/endpoints/ep-a/tickets", "ui", `{"reasonRequired":false}`)
	token := out["token"].(string)
	r.lookupErr.Store(true)
	if res := r.redeem(t, token, "", redeemOpts{}); res.status != 503 || res.cookie != "" {
		t.Fatalf("redeem with failing lookup: %d %s (cookie set: %v)", res.status, res.raw, res.cookie != "")
	}
	r.lookupErr.Store(false)
	if res := r.redeem(t, token, "", redeemOpts{}); res.status != 202 {
		t.Fatalf("retry after the failure: %d %s", res.status, res.raw)
	}
}
