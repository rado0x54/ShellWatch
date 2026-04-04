package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
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
