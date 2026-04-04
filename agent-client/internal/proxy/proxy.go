// Package proxy implements the SSH agent protocol relay between
// a local Unix socket and a remote ShellWatch WebSocket endpoint.
package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type ProxyConfig struct {
	SocketPath string
	ServerURL  string
	ApiKey     string
	Insecure   bool
}

// Run starts the agent proxy. It listens on a Unix socket and relays
// SSH agent protocol frames over WebSocket to the ShellWatch server.
// Blocks until interrupted.
func Run(cfg ProxyConfig) error {
	// Clean up stale socket
	if err := cleanStaleSocket(cfg.SocketPath); err != nil {
		return fmt.Errorf("socket path in use: %w", err)
	}

	listener, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.SocketPath, err)
	}

	// Set socket permissions to owner-only (0600)
	if err := os.Chmod(cfg.SocketPath, 0600); err != nil {
		listener.Close()
		return fmt.Errorf("chmod socket: %w", err)
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
	fmt.Fprintf(os.Stderr, "  export SSH_AUTH_SOCK=%s\n", cfg.SocketPath)

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		listener.Close()
		os.Remove(cfg.SocketPath)
	}()

	// WebSocket connection cache (reuse across sequential agent operations)
	cache := &wsCache{
		url:    wsURL,
		apiKey: cfg.ApiKey,
	}
	defer cache.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed (shutdown)
			return nil
		}
		go handleConnection(conn, cache)
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
// The OpenSSH client opens a new connection per agent operation,
// so each connection is typically a single request-response pair.
func handleConnection(conn net.Conn, cache *wsCache) {
	defer conn.Close()

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

		// Get or create a WebSocket connection
		ws, err := cache.Get()
		if err != nil {
			log.Printf("WebSocket connect error: %v", err)
			return
		}

		// Send frame as binary WebSocket message
		if err := ws.WriteMessage(websocket.BinaryMessage, frame); err != nil {
			log.Printf("WebSocket write error: %v", err)
			cache.Invalidate()
			return
		}

		// Read response
		msgType, response, err := ws.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			cache.Invalidate()
			return
		}
		if msgType != websocket.BinaryMessage {
			log.Printf("Unexpected WebSocket message type: %d", msgType)
			cache.Invalidate()
			return
		}

		// Write response back to the Unix socket
		if _, err := conn.Write(response); err != nil {
			log.Printf("Socket write error: %v", err)
			return
		}
	}
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

// wsCache provides a reusable WebSocket connection with automatic
// refresh. Connections are kept alive for 30 seconds to amortize
// TLS handshake cost across sequential getIdentities → sign calls.
type wsCache struct {
	url    string
	apiKey string
	mu     sync.Mutex
	conn   *websocket.Conn
	timer  *time.Timer
}

const wsCacheTTL = 30 * time.Second

func (c *wsCache) Get() (*websocket.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		// Reset TTL
		if c.timer != nil {
			c.timer.Reset(wsCacheTTL)
		}
		return c.conn, nil
	}

	// Dial new connection
	header := http.Header{}
	header.Set("Authorization", "Bearer "+c.apiKey)

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(c.url, header)
	if err != nil {
		return nil, err
	}

	c.conn = conn
	c.timer = time.AfterFunc(wsCacheTTL, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
	})

	return conn, nil
}

func (c *wsCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
}

func (c *wsCache) Close() {
	c.Invalidate()
}

// cleanStaleSocket removes a socket file if it exists but no one is listening.
func cleanStaleSocket(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	// Try to connect — if it succeeds, something is already listening
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		conn.Close()
		return fmt.Errorf("another process is listening on %s", path)
	}

	// Stale socket — remove it
	return os.Remove(path)
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
