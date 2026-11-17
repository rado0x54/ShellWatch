// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package terminal

import (
	"reflect"
	"testing"
	"time"
)

func TestSessionViewsView(t *testing.T) {
	created := time.Date(2026, 11, 17, 9, 30, 0, 123e6, time.FixedZone("CET", 3600))
	base := func(id string, src Source) Session {
		return Session{
			SessionID: id, EndpointID: "ep", AccountID: "acc", Status: StatusOpen,
			CreatedAt: created, Source: src, SourceIP: "203.0.113.7",
		}
	}
	mcp := base("sess_mcp", SourceMCP)
	mcp.Origin = Origin{OwnerClientID: "client-1", Reason: "deploy", MCPClientName: "codex", MCPClientVer: "1.2.3"}
	ticket := base("sess_tk", SourceTicket)
	ticket.Origin = Origin{Reason: "fix", TicketID: "tk_1", TicketLabel: "Printer fix", TicketChannel: TicketChannelWeb}

	guests := map[string]bool{} // sessionID -> attached; missing -> gone
	views := SessionViews{GuestAttached: func(id string) (bool, bool) {
		a, ok := guests[id]
		return a, ok
	}}
	label, yes, no := "Printer fix", true, false
	shared := func(id, src string) SessionView {
		return SessionView{SessionID: id, EndpointID: "ep", Status: "open", CreatedAt: "2026-11-17T08:30:00.123Z", Source: src}
	}
	withTicket := func(attached *bool) SessionView {
		v := shared("sess_tk", "ticket")
		v.TicketID, v.TicketLabel, v.GuestAttached = "tk_1", &label, attached
		return v
	}

	for _, tc := range []struct {
		name   string
		sess   Session
		guests map[string]bool
		want   SessionView
	}{
		{"ui", base("sess_ui", SourceUI), nil, shared("sess_ui", "ui")},
		{"mcp", mcp, nil, shared("sess_mcp", "mcp")},
		{"ticket attached", ticket, map[string]bool{"sess_tk": true}, withTicket(&yes)},
		{"ticket away", ticket, map[string]bool{"sess_tk": false}, withTicket(&no)},
		{"ticket gone", ticket, nil, withTicket(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guests = tc.guests
			if got := views.View(tc.sess); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("View() = %+v, want %+v", got, tc.want)
			}
		})
	}
	// A nil lookup (guests disabled) never reports guestAttached.
	if got := (SessionViews{}).View(ticket); got.GuestAttached != nil {
		t.Fatalf("nil lookup: guestAttached = %v, want absent", *got.GuestAttached)
	}
}
