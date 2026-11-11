// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package agentproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/rado0x54/shellwatch/internal/auth"
)

// An inbound message over MaxFrameBytes closes the link with 1009 instead
// of being buffered whole.
func TestAgentProxyRejectsOversizedFrame(t *testing.T) {
	deps := &Deps{Credentials: emptyCreds{}, FileKeys: staticSigners{}, RpID: "localhost"}
	handler := auth.WithPrincipal(deps.Handler(), auth.Principal{AccountID: "acc", Scopes: []string{"agent"}})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/agent-proxy"
	wsc, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { wsc.CloseNow() })

	// The write itself may fail once the server closes mid-message; the
	// close status on the next read is what's asserted.
	_ = wsc.Write(ctx, websocket.MessageBinary, make([]byte, MaxFrameBytes+1))
	_, _, err = wsc.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.StatusMessageTooBig {
		t.Fatalf("read after oversized frame: err=%v, want close 1009", err)
	}
}

// Every inbound message must be exactly one agent frame within the payload
// cap. Otherwise a client could stream an oversized frame across many small
// messages, under SetReadLimit, and ServeAgent would allocate whatever the
// length prefix declares. Each case closes with 4000 (malformed frame).
func TestAgentProxyRejectsMalformedFrames(t *testing.T) {
	prefix := func(n uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, n); return b }
	// SSH_AGENTC_REQUEST_IDENTITIES (type 11) as one well-formed frame.
	list := append(prefix(1), 11)

	cases := []struct {
		name string
		msgs [][]byte
	}{
		{"prefix alone declaring 16 MiB", [][]byte{prefix(16 << 20)}},
		{"frame over the payload cap split across messages", [][]byte{
			prefix(MaxPayloadBytes + 1), make([]byte, MaxPayloadBytes/2), make([]byte, MaxPayloadBytes/2+1),
		}},
		{"declared length longer than the message", [][]byte{append(prefix(10), 11)}},
		{"two frames in one message", [][]byte{append(append([]byte{}, list...), list...)}},
		{"shorter than a length prefix", [][]byte{{0, 0}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := &Deps{Credentials: emptyCreds{}, FileKeys: staticSigners{}, RpID: "localhost"}
			handler := auth.WithPrincipal(deps.Handler(), auth.Principal{AccountID: "acc", Scopes: []string{"agent"}})
			ts := httptest.NewServer(handler)
			t.Cleanup(ts.Close)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			wsc, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/agent-proxy", nil)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			t.Cleanup(func() { wsc.CloseNow() })

			for _, m := range tc.msgs {
				// Later writes may fail once the server has closed.
				_ = wsc.Write(ctx, websocket.MessageBinary, m)
			}
			_, _, err = wsc.Read(ctx)
			if got := websocket.CloseStatus(err); got != 4000 {
				t.Fatalf("got err=%v (close %d), want close 4000", err, got)
			}
		})
	}
}

func TestValidFrame(t *testing.T) {
	frame := func(n int) []byte {
		b := make([]byte, 4+n)
		binary.BigEndian.PutUint32(b, uint32(n))
		return b
	}
	cases := []struct {
		name string
		msg  []byte
		want bool
	}{
		{"empty payload", frame(0), true},
		{"payload at the cap", frame(MaxPayloadBytes), true},
		{"payload over the cap", frame(MaxPayloadBytes + 1), false},
		{"truncated prefix", []byte{0, 0, 1}, false},
		{"trailing bytes", append(frame(1), 0), false},
		{"declared longer than message", frame(2)[:5], false},
	}
	for _, tc := range cases {
		if got := validFrame(tc.msg); got != tc.want {
			t.Errorf("%s: validFrame = %v, want %v", tc.name, got, tc.want)
		}
	}
}
