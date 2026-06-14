// SPDX-License-Identifier: MIT
// Package proxy implements the SSH agent protocol relay between a local
// listener (Unix domain socket on macOS/Linux, named pipe on Windows) and
// a remote ShellWatch WebSocket endpoint.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rado0x54/shellwatch-agent/internal/oauth"
)

// Tunables for keepalive + reconnect.
const (
	// pingInterval is how often we send a WebSocket ping.
	pingInterval = 30 * time.Second
	// pongWait is the read deadline; if no data or pong arrives within this
	// window, the connection is considered dead. With a 30 s ping cadence and
	// 60 s deadline, stale links are detected ~1 min after they break,
	// instead of waiting for the OS TCP keepalive (often 2 h).
	pongWait = 60 * time.Second
	// pingWriteTimeout caps how long a ping write can block.
	pingWriteTimeout = 10 * time.Second

	// dialInitialBackoff is the first retry wait after a transient dial failure.
	dialInitialBackoff = 500 * time.Millisecond
	// dialMaxBackoff caps the exponential backoff.
	dialMaxBackoff = 30 * time.Second
	// dialBudget caps the total time a single dialWithRetry spends before
	// giving up — keeps the calling SSH client from hanging indefinitely.
	dialBudget = 60 * time.Second
)

type ProxyConfig struct {
	SocketPath string
	ServerURL  string
	// Token yields the bearer for each WebSocket dial. Re-read per dial so a
	// client_credentials source can transparently refresh the access token.
	Token    oauth.Tokener
	Insecure bool
	Version  string
}

// Run starts the agent proxy. It listens on a local socket (Unix domain
// socket on macOS/Linux, named pipe on Windows) and relays SSH agent
// protocol frames over WebSocket to the ShellWatch server.
// Blocks until interrupted.
func Run(cfg ProxyConfig) error {
	if err := cleanStaleSocket(cfg.SocketPath); err != nil {
		return fmt.Errorf("socket path in use: %w", err)
	}

	listener, err := listenSocket(cfg.SocketPath)
	if err != nil {
		return err
	}

	// Build WebSocket URL
	wsURL, err := buildWSURL(cfg.ServerURL)
	if err != nil {
		listener.Close()
		return fmt.Errorf("invalid server URL: %w", err)
	}
	if !cfg.Insecure && !strings.HasPrefix(wsURL, "wss://") {
		listener.Close()
		return fmt.Errorf("server URL must use https:// (or use --insecure for http://)")
	}

	log.Printf("ShellWatch agent proxy listening on %s", cfg.SocketPath)
	log.Printf("Connected to %s", cfg.ServerURL)
	fmt.Fprintf(os.Stderr, "  SSH_AUTH_SOCK=%s\n", cfg.SocketPath)

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		listener.Close()
		removeSocketFile(cfg.SocketPath)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed (shutdown)
			return nil
		}
		go handleConnection(conn, wsURL, cfg.Token, cfg.Version)
	}
}

// SSH agent protocol message types
const (
	sshAgentFailure    = 5
	sshAgentcExtension = 27
)

// agentFailureResponse is a pre-built SSH_AGENT_FAILURE frame.
// Format: uint32(1) + byte(5) = 5 bytes total.
var agentFailureResponse = []byte{0, 0, 0, 1, sshAgentFailure}

// handleConnection processes one SSH agent client connection.
// Each connection gets its own WebSocket to the server, ensuring
// clean protocol state isolation between concurrent SSH clients.
func handleConnection(conn net.Conn, wsURL string, token oauth.Tokener, version string) {
	defer conn.Close()

	var ws *managedWS
	defer func() {
		if ws != nil {
			ws.Close()
		}
	}()

	for {
		// Read one complete SSH agent protocol frame:
		// 4 bytes big-endian length + `length` bytes payload
		frame, err := readFrame(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read frame error: %v", err)
			}
			return
		}

		// Handle extension messages locally. Newer OpenSSH sends
		// SSH_AGENTC_EXTENSION (type 27) for session binding before
		// requesting identities. ssh2's AgentProtocol has a bug where
		// unknown message types with payloads corrupt the parse buffer.
		// Respond with FAILURE here (which is the correct response for
		// unsupported extensions) without forwarding to the server.
		if len(frame) >= 5 && frame[4] == sshAgentcExtension {
			if _, err := conn.Write(agentFailureResponse); err != nil {
				log.Printf("Socket write error: %v", err)
				return
			}
			continue
		}

		// Lazily dial the WebSocket on first real agent message.
		// dialWithRetry handles transient network failures (laptop just
		// woke up, WiFi switching, DNS hiccup) with exponential backoff.
		if ws == nil {
			ws, err = dialWithRetry(wsURL, token, version)
			if err != nil {
				log.Printf("WebSocket connect error: %v", err)
				return
			}
		}

		// Send frame as binary WebSocket message
		if err := ws.WriteMessage(websocket.BinaryMessage, frame); err != nil {
			log.Printf("WebSocket write error: %v", err)
			return
		}

		// Read response
		msgType, response, err := ws.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			return
		}
		if msgType != websocket.BinaryMessage {
			log.Printf("Unexpected WebSocket message type: %d", msgType)
			return
		}

		// Write response back to the Unix socket
		if _, err := conn.Write(response); err != nil {
			log.Printf("Socket write error: %v", err)
			return
		}
	}
}

// managedWS wraps a *websocket.Conn with WebSocket-level keepalive.
// A background goroutine sends pings every pingInterval; the read deadline
// is bumped on every successful read and on every pong. If the connection
// goes silent (no data, no pong) for pongWait, ReadMessage returns an
// error instead of hanging on the OS TCP keepalive (which is often hours).
type managedWS struct {
	conn     *websocket.Conn
	stopPing chan struct{}
	pingDone chan struct{}
}

func newManagedWS(conn *websocket.Conn) *managedWS {
	m := &managedWS{
		conn:     conn,
		stopPing: make(chan struct{}),
		pingDone: make(chan struct{}),
	}
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	go m.pingLoop()
	return m
}

func (m *managedWS) pingLoop() {
	defer close(m.pingDone)
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopPing:
			return
		case <-ticker.C:
			// WriteControl is documented as safe to call concurrently
			// with the regular write methods.
			if err := m.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(pingWriteTimeout)); err != nil {
				return
			}
		}
	}
}

func (m *managedWS) WriteMessage(messageType int, data []byte) error {
	return m.conn.WriteMessage(messageType, data)
}

func (m *managedWS) ReadMessage() (int, []byte, error) {
	msgType, data, err := m.conn.ReadMessage()
	if err == nil {
		// Successful read counts as liveness — bump the deadline.
		_ = m.conn.SetReadDeadline(time.Now().Add(pongWait))
	}
	return msgType, data, err
}

func (m *managedWS) Close() error {
	select {
	case <-m.stopPing:
	default:
		close(m.stopPing)
	}
	err := m.conn.Close()
	<-m.pingDone
	return err
}

// dialWithRetry calls dialOnce, retrying with exponential backoff
// (capped at dialMaxBackoff, total time capped at dialBudget) when the
// failure looks transient. On non-transient failures (bad URL, auth
// rejection, etc.) it returns immediately.
func dialWithRetry(wsURL string, token oauth.Tokener, version string) (*managedWS, error) {
	deadline := time.Now().Add(dialBudget)
	backoff := dialInitialBackoff
	attempt := 0
	for {
		attempt++
		conn, resp, err := dialOnce(wsURL, token, version)
		if err == nil {
			if attempt > 1 {
				log.Printf("WebSocket reconnected after %d attempt(s)", attempt)
			}
			return newManagedWS(conn), nil
		}
		if !isTransientDialErr(err, resp) {
			return nil, err
		}
		if time.Now().Add(backoff).After(deadline) {
			return nil, fmt.Errorf("dial retries exhausted after %d attempt(s): %w", attempt, err)
		}
		log.Printf("dial failed (attempt %d), retry in %s: %v", attempt, backoff, err)
		time.Sleep(backoff)
		backoff = nextBackoff(backoff)
	}
}

// dialOnce performs a single WebSocket dial. The bearer is fetched fresh from
// the token source so a client_credentials access token is refreshed as needed.
func dialOnce(wsURL string, token oauth.Tokener, version string) (*websocket.Conn, *http.Response, error) {
	bearer, err := token.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("acquire access token: %w", err)
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+bearer)

	// Best-effort client metadata advertised to the server so it can show a
	// richer "who is asking?" context on the /sign/:id approval page. All
	// three headers are optional; the server falls back gracefully when absent.
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		header.Set("X-ShellWatch-Hostname", hostname)
	}
	header.Set("X-ShellWatch-OS", runtime.GOOS+"/"+runtime.GOARCH)
	if version != "" {
		header.Set("X-ShellWatch-Version", version)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	return dialer.Dial(wsURL, header)
}

// nextBackoff doubles the current wait, capped at dialMaxBackoff.
func nextBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > dialMaxBackoff {
		return dialMaxBackoff
	}
	return next
}

// isTransientDialErr returns true when the dial failure looks worth
// retrying — network blips, DNS hiccups, server restarts. Auth failures,
// TLS/cert validation failures, and protocol errors are not retried.
func isTransientDialErr(err error, resp *http.Response) bool {
	if err == nil {
		return false
	}
	// On bad-handshake errors gorilla/websocket attaches the HTTP response.
	if resp != nil {
		// Retry on 5xx and a few transient 4xx (request timeout, too many requests).
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests {
			return true
		}
		// Other 4xx (e.g., 401/403/404) are not transient.
		return false
	}
	// TLS / certificate validation failures will never succeed with the same
	// config — don't burn the retry budget on them. Check before the generic
	// net.Error arm because *tls.CertificateVerificationError is wrapped in
	// *net.OpError, which implements net.Error.
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return false
	}
	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		return false
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return false
	}
	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return false
	}
	// Network-layer errors (connection refused, no route to host, DNS, EOF)
	// are typically *net.OpError / *url.Error wrapping these. *net.DNSError
	// also implements net.Error, so it's caught by this arm.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return false
}

// readFrame reads one complete SSH agent protocol frame from the connection.
// Format: 4 bytes big-endian length + `length` bytes payload.
// Returns the complete frame including the length prefix.
func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}

	payloadLen := binary.BigEndian.Uint32(lenBuf[:])
	if payloadLen > 256*1024 { // 256 KB max — generous for SSH agent
		return nil, fmt.Errorf("frame too large: %d bytes", payloadLen)
	}

	frame := make([]byte, 4+payloadLen)
	copy(frame[:4], lenBuf[:])
	if _, err := io.ReadFull(r, frame[4:]); err != nil {
		return nil, err
	}

	return frame, nil
}

// buildWSURL converts an HTTP(S) server URL to its WebSocket equivalent
// and appends the /agent-proxy path.
func buildWSURL(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", err
	}

	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "wss", "ws":
		// Already a WebSocket URL
	default:
		return "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	u.Path = strings.TrimRight(u.Path, "/") + "/agent-proxy"
	return u.String(), nil
}
