// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package agentproxy

import (
	"context"
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
