// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package terminal

import (
	"bytes"
	"strings"
	"testing"
)

func TestBufferReadAndOffsets(t *testing.T) {
	b := NewOutputBuffer(0)
	b.Append([]byte("hello "))
	b.Append([]byte("world"))
	if got := b.CurrentOffset(); got != 11 {
		t.Fatalf("offset: %d", got)
	}
	r := b.Read(0, 5)
	if string(r.Data) != "hello" || r.Offset != 5 || !r.HasMore {
		t.Fatalf("read: %q off=%d more=%v", r.Data, r.Offset, r.HasMore)
	}
	r2 := b.Read(r.Offset, 100)
	if string(r2.Data) != " world" || r2.Offset != 11 || r2.HasMore {
		t.Fatalf("read2: %q off=%d more=%v", r2.Data, r2.Offset, r2.HasMore)
	}
}

func TestBufferByteOffsetsMultibyte(t *testing.T) {
	// A 4-byte emoji advances the offset by 4 (byte-based, W6/parity item K),
	// not by 1 or 2 as a UTF-16-string buffer would.
	b := NewOutputBuffer(0)
	emoji := "\U0001F600" // 4 UTF-8 bytes
	b.Append([]byte(emoji))
	if got := b.CurrentOffset(); got != 4 {
		t.Fatalf("emoji offset should be 4 bytes, got %d", got)
	}
}

func TestBufferEvictionAndReset(t *testing.T) {
	b := NewOutputBuffer(4)
	b.Append([]byte("abcdef")) // over cap -> keeps "cdef", baseOffset=2
	if b.CurrentOffset() != 6 {
		t.Fatalf("offset: %d", b.CurrentOffset())
	}
	// An offset behind the ring is unrecoverable -> reset.
	stale := int64(0)
	fr := b.ReadFrom(&stale)
	if !fr.Reset || string(fr.Data) != "cdef" {
		t.Fatalf("expected reset with full tail, got reset=%v %q", fr.Reset, fr.Data)
	}
	// Current offset -> empty, no reset.
	cur := b.CurrentOffset()
	if fr := b.ReadFrom(&cur); fr.Reset || len(fr.Data) != 0 {
		t.Fatalf("at-current should be empty no-reset, got %v %q", fr.Reset, fr.Data)
	}
}

func TestBufferTailAdvancesToEscape(t *testing.T) {
	b := NewOutputBuffer(0)
	// "aa" then ESC then "bbb": a 4-byte tail cuts to "a\x1bbbb"->"a"+ESC..., and
	// the ESC at index 1 of the slice advances the cut to the ESC (never hands
	// a renderer a leading plain byte before a half sequence).
	b.Append([]byte("aa\x1bbbb"))
	tail := b.Tail(4)
	if !bytes.HasPrefix(tail, []byte("\x1b")) {
		t.Fatalf("tail should advance to ESC, got %q", tail)
	}
	// Whole buffer when limit exceeds length.
	if got := b.Tail(1000); string(got) != "aa\x1bbbb" {
		t.Fatalf("full tail: %q", got)
	}
	_ = strings.Count
}
