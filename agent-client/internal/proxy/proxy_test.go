package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestReadFrame(t *testing.T) {
	// Build a valid SSH agent frame: 4-byte length + payload
	payload := []byte{11} // SSH_AGENTC_REQUEST_IDENTITIES
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(payload)))
	buf.Write(payload)

	frame, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if len(frame) != 5 {
		t.Fatalf("expected frame length 5, got %d", len(frame))
	}
	if frame[4] != 11 {
		t.Fatalf("expected message type 11, got %d", frame[4])
	}
}

func TestReadFrameEOF(t *testing.T) {
	var buf bytes.Buffer
	_, err := readFrame(&buf)
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestReadFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(512*1024)) // 512 KB
	buf.Write(make([]byte, 100))

	_, err := readFrame(&buf)
	if err == nil {
		t.Fatal("expected error for oversized frame")
	}
}

func TestReadFrameExtensionType(t *testing.T) {
	// SSH_AGENTC_EXTENSION (type 27) with an extension name payload
	extName := []byte("session-bind@openssh.com")
	payload := append([]byte{27}, extName...) // type 27 + extension name
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(payload)))
	buf.Write(payload)

	frame, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}

	// Verify the message type is correctly at frame[4]
	if frame[4] != 27 {
		t.Fatalf("expected message type 27, got %d", frame[4])
	}

	// Verify our extension detection logic works
	if len(frame) < 5 || frame[4] != sshAgentcExtension {
		t.Fatal("extension detection failed")
	}
}

func TestAgentFailureResponse(t *testing.T) {
	// Verify the pre-built failure response is well-formed
	if len(agentFailureResponse) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(agentFailureResponse))
	}
	payloadLen := binary.BigEndian.Uint32(agentFailureResponse[:4])
	if payloadLen != 1 {
		t.Fatalf("expected payload length 1, got %d", payloadLen)
	}
	if agentFailureResponse[4] != sshAgentFailure {
		t.Fatalf("expected type %d, got %d", sshAgentFailure, agentFailureResponse[4])
	}
}

func TestNextBackoff(t *testing.T) {
	cur := dialInitialBackoff
	// Doubling should eventually saturate at dialMaxBackoff.
	for i := 0; i < 20; i++ {
		next := nextBackoff(cur)
		if next < cur && cur < dialMaxBackoff {
			t.Errorf("backoff should not decrease before cap: cur=%v next=%v", cur, next)
		}
		if next > dialMaxBackoff {
			t.Errorf("backoff exceeded cap: %v > %v", next, dialMaxBackoff)
		}
		cur = next
	}
	if cur != dialMaxBackoff {
		t.Errorf("expected backoff to saturate at %v, got %v", dialMaxBackoff, cur)
	}
}

func TestIsTransientDialErr(t *testing.T) {
	dnsErr := &net.DNSError{Err: "no such host", Name: "missing.invalid"}
	netErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}

	tests := []struct {
		name string
		err  error
		resp *http.Response
		want bool
	}{
		{"nil error", nil, nil, false},
		{"DNS error", dnsErr, nil, true},
		{"network op error", netErr, nil, true},
		{"unexpected EOF", io.ErrUnexpectedEOF, nil, true},
		{"500", websocket.ErrBadHandshake, &http.Response{StatusCode: 500}, true},
		{"503", websocket.ErrBadHandshake, &http.Response{StatusCode: 503}, true},
		{"408", websocket.ErrBadHandshake, &http.Response{StatusCode: 408}, true},
		{"429", websocket.ErrBadHandshake, &http.Response{StatusCode: 429}, true},
		{"401", websocket.ErrBadHandshake, &http.Response{StatusCode: 401}, false},
		{"403", websocket.ErrBadHandshake, &http.Response{StatusCode: 403}, false},
		{"404", websocket.ErrBadHandshake, &http.Response{StatusCode: 404}, false},
		{"plain error", errors.New("nope"), nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransientDialErr(tt.err, tt.resp); got != tt.want {
				t.Errorf("isTransientDialErr = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDialWithRetry_RecoversAfterTransientFailures wraps a real test server
// that rejects the first two dials and accepts the third — verifies that
// dialWithRetry retries and ultimately succeeds.
func TestDialWithRetry_RecoversAfterTransientFailures(t *testing.T) {
	upgrader := websocket.Upgrader{}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			http.Error(w, "warming up", http.StatusServiceUnavailable)
			return
		}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = c.Close()
	}))
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL)
	u.Scheme = "ws"

	// Tighten the budget so this test runs fast — the production dial timing
	// would still complete, but we want to keep the test cheap.
	ws, err := dialWithRetry(u.String(), "test-key", "test")
	if err != nil {
		t.Fatalf("dialWithRetry: %v", err)
	}
	defer ws.Close()
	if got := calls.Load(); got < 3 {
		t.Errorf("expected at least 3 dial attempts, got %d", got)
	}
}

// TestDialWithRetry_DoesNotRetryOnAuthRejection ensures we fail fast on
// non-transient errors (auth failure) instead of waiting through the budget.
func TestDialWithRetry_DoesNotRetryOnAuthRejection(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL)
	u.Scheme = "ws"

	start := time.Now()
	_, err := dialWithRetry(u.String(), "test-key", "test")
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("auth rejection should fail fast, took %v", elapsed)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("auth rejection should not retry, got %d attempt(s)", got)
	}
}

func TestBuildWSURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com", "wss://example.com/agent-proxy"},
		{"http://localhost:3000", "ws://localhost:3000/agent-proxy"},
		{"https://example.com/sw", "wss://example.com/sw/agent-proxy"},
		{"https://example.com/sw/", "wss://example.com/sw/agent-proxy"},
		{"wss://example.com", "wss://example.com/agent-proxy"},
	}

	for _, tt := range tests {
		got, err := buildWSURL(tt.input)
		if err != nil {
			t.Errorf("buildWSURL(%q): %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("buildWSURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
