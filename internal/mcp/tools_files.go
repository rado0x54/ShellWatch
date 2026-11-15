// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// File tools (#263): inline list/read/write for small files and
// shellwatch_transfer_file for out-of-band streaming of large ones. All of
// them run over the SFTP subsystem of an OPEN session the human already
// approved — no new signature, no approval gate; every operation is audited
// and shown live to anyone watching the session. Ownership is the session's
// (account, OAuth client), with the uniform "session not found" error.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/transfer"
)

// fileSemantics is the shared part of every file tool's description: the
// SFTP subsystem does NOT share the PTY's shell state.
const fileSemantics = " Runs over SFTP as the SSH LOGIN USER, independent of the terminal: it does not follow the shell's working directory, `cd`, or `sudo`. Paths must be absolute. If the login user lacks permission, the call fails with the SFTP error — fall back to the terminal (e.g. `sudo tee`)."

var modeSchema = map[string]any{
	"type":        []string{"integer", "string"},
	"description": `Permission bits, at most 0777 (setuid/setgid/sticky are refused). Prefer an octal STRING such as "0644" or "600"; a JSON number is taken at its numeric value (420 == 0o644), not as octal digits.`,
}

// parseMode decodes the tools' mode argument: an octal string ("0644") or a
// number holding the permission bits themselves. Anything above 0777 —
// including the classic decimal-digits mistake (644 == 0o1204) — is refused.
func parseMode(raw json.RawMessage) (*os.FileMode, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	const hint = `mode must be permission bits up to 0777: an octal string like "0644", or the numeric value (420 for 0o644)`
	var bits uint64
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		v, err := strconv.ParseUint(s, 8, 32)
		if err != nil {
			return nil, errors.New(hint)
		}
		bits = v
	} else {
		var f float64
		if err := json.Unmarshal(raw, &f); err != nil || f < 0 || f != float64(uint64(f)) {
			return nil, errors.New(hint)
		}
		bits = uint64(f)
	}
	if bits > 0o777 {
		return nil, errors.New(hint + "; setuid/setgid/sticky bits are refused")
	}
	mode := os.FileMode(bits)
	return &mode, nil
}

func registerFileTools(srv *mcpsdk.Server, as *agent.Session, svc *transfer.Service) {
	lim := svc.Limits()
	caller := func(req *mcpsdk.CallToolRequest) transfer.Caller {
		captureClientInfo(as, req)
		name, version := as.ClientInfo()
		return transfer.Caller{
			AccountID: as.AccountID(), ClientID: as.ClientID(),
			ClientName: name, ClientVersion: version, SourceIP: as.SourceIP(),
		}
	}

	srv.AddTool(&mcpsdk.Tool{
		Name: "shellwatch_list_dir",
		Description: "List a directory on the remote host of an open session. Entries are sorted by name and carry type (file, directory, symlink, fifo, socket, device), size, mode and mtime; symlinks include their target." +
			fileSemantics,
		InputSchema: objSchema(map[string]any{
			"sessionId":  map[string]any{"type": "string"},
			"path":       map[string]any{"type": "string", "description": "Absolute directory path"},
			"maxEntries": map[string]any{"type": "number", "description": "Maximum entries to return (default 200, cap 1000); `truncated` reports whether more exist."},
		}, "sessionId", "path"),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		var args struct {
			SessionID  string `json:"sessionId"`
			Path       string `json:"path"`
			MaxEntries int    `json:"maxEntries"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult(err.Error()), nil
		}
		if err := as.AssertOwned(args.SessionID); err != nil {
			return errResult(err.Error()), nil
		}
		res, err := svc.ListDir(ctx, caller(req), args.SessionID, args.Path, args.MaxEntries)
		if err != nil {
			return errResult(err.Error()), nil
		}
		return jsonResult(res)
	})

	srv.AddTool(&mcpsdk.Tool{
		Name: "shellwatch_read_file",
		Description: fmt.Sprintf("Read a small file (up to %d bytes) from the remote host of an open session, with its size, mode, mtime and sha256. Use encoding \"base64\" for binary content. Larger files fail with a hint — use shellwatch_transfer_file instead; partial content is never returned. Symlinks are followed; directories and special files are refused.", lim.MaxInlineBytes) +
			fileSemantics,
		InputSchema: objSchema(map[string]any{
			"sessionId": map[string]any{"type": "string"},
			"path":      map[string]any{"type": "string", "description": "Absolute file path"},
			"encoding":  map[string]any{"type": "string", "enum": []string{"utf8", "base64"}, "description": "Content encoding of the result (default utf8)"},
		}, "sessionId", "path"),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		var args struct {
			SessionID string `json:"sessionId"`
			Path      string `json:"path"`
			Encoding  string `json:"encoding"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult(err.Error()), nil
		}
		if err := as.AssertOwned(args.SessionID); err != nil {
			return errResult(err.Error()), nil
		}
		res, err := svc.ReadFile(ctx, caller(req), args.SessionID, args.Path, args.Encoding)
		if err != nil {
			return errResult(err.Error()), nil
		}
		return jsonResult(res)
	})

	srv.AddTool(&mcpsdk.Tool{
		Name: "shellwatch_write_file",
		Description: fmt.Sprintf("Write a small file (up to %d decoded bytes) on the remote host of an open session. overwrite=false (default) creates the file exclusively and fails if it exists; overwrite=true truncates in place, preserving inode, owner, mode and hard links (a supplied mode then overrides the existing one). A destination that is a symlink, directory or special file is refused. New files get mode 0644 unless `mode` is given; the mode is set on the still-empty file before content is written, but a reader that opened it in that instant keeps its descriptor — for secrets prefer shellwatch_transfer_file, which stages privately. For larger or binary payloads use shellwatch_transfer_file.", lim.MaxInlineBytes) +
			fileSemantics,
		InputSchema: objSchema(map[string]any{
			"sessionId": map[string]any{"type": "string"},
			"path":      map[string]any{"type": "string", "description": "Absolute file path"},
			"content":   map[string]any{"type": "string"},
			"encoding":  map[string]any{"type": "string", "enum": []string{"utf8", "base64"}, "description": "Encoding of `content` (default utf8)"},
			"overwrite": map[string]any{"type": "boolean", "description": "Replace an existing file in place (default false)"},
			"mode":      modeSchema,
		}, "sessionId", "path", "content"),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		var args struct {
			SessionID string          `json:"sessionId"`
			Path      string          `json:"path"`
			Content   string          `json:"content"`
			Encoding  string          `json:"encoding"`
			Overwrite bool            `json:"overwrite"`
			Mode      json.RawMessage `json:"mode"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult(err.Error()), nil
		}
		if err := as.AssertOwned(args.SessionID); err != nil {
			return errResult(err.Error()), nil
		}
		mode, err := parseMode(args.Mode)
		if err != nil {
			return errResult(err.Error()), nil
		}
		res, err := svc.WriteFile(ctx, caller(req), transfer.WriteParams{
			SessionID: args.SessionID, Path: args.Path, Content: args.Content,
			Encoding: args.Encoding, Overwrite: args.Overwrite, Mode: mode,
		})
		if err != nil {
			return errResult(err.Error()), nil
		}
		return jsonResult(res)
	})

	srv.AddTool(&mcpsdk.Tool{
		Name: "shellwatch_transfer_file",
		Description: fmt.Sprintf("Move a large or binary file to/from the remote host of an open session WITHOUT passing the bytes through this conversation. action \"create\" mints a short-lived (%d s), single-use URL and an exact curl command; run that command in your shell or sandbox, then call action \"status\" with the transferId to learn the outcome (curl's output never reaches the server). action \"cancel\" aborts a transfer that has not committed yet. "+
			"Uploads (direction \"upload\", HTTP PUT) are staged in a private directory next to the destination and committed atomically: overwrite=false fails if the destination exists, overwrite=true replaces it. The commit creates a NEW inode, so owner, ACLs and hard links of a replaced file are not preserved (use shellwatch_write_file for that). `sha256` makes the server verify the upload. Requires an OpenSSH-compatible sftp-server (posix-rename + hardlink extensions). "+
			"Downloads (direction \"download\", HTTP GET) send the file as it is when opened; status \"completed\" means the server finished sending, `truncated: true` means the file was observed to grow afterwards, and a live database file gives no consistency guarantee. "+
			"A failed status with commitOutcome \"unknown\" means the connection dropped mid-commit: inspect the destination before retrying. cleanup \"failed\" names a leftover stagingPath. The host running curl must reach this server and be inside its allowed networks. Limit: %d bytes per transfer.", lim.LinkTtlSeconds, lim.MaxTransferBytes) +
			fileSemantics,
		InputSchema: objSchema(map[string]any{
			"action":     map[string]any{"type": "string", "enum": []string{"create", "status", "cancel"}},
			"sessionId":  map[string]any{"type": "string", "description": "create: the open session to transfer through"},
			"direction":  map[string]any{"type": "string", "enum": []string{"upload", "download"}, "description": "create: upload = local → remote, download = remote → local"},
			"path":       map[string]any{"type": "string", "description": "create: absolute remote file path"},
			"maxBytes":   map[string]any{"type": "number", "description": "create: byte cap for this transfer (default and maximum: the server limit)"},
			"sha256":     map[string]any{"type": "string", "description": "create, upload only: expected hex digest; a mismatch fails the transfer before commit"},
			"overwrite":  map[string]any{"type": "boolean", "description": "create, upload only: replace an existing destination (default false)"},
			"mode":       modeSchema,
			"transferId": map[string]any{"type": "string", "description": "status / cancel: the id returned by create"},
		}, "action"),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		var args struct {
			Action     string          `json:"action"`
			SessionID  string          `json:"sessionId"`
			Direction  string          `json:"direction"`
			Path       string          `json:"path"`
			MaxBytes   int64           `json:"maxBytes"`
			SHA256     string          `json:"sha256"`
			Overwrite  bool            `json:"overwrite"`
			Mode       json.RawMessage `json:"mode"`
			TransferID string          `json:"transferId"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult(err.Error()), nil
		}
		c := caller(req)
		switch args.Action {
		case "create":
			if args.SessionID == "" {
				return errResult("sessionId is required"), nil
			}
			if err := as.AssertOwned(args.SessionID); err != nil {
				return errResult(err.Error()), nil
			}
			mode, err := parseMode(args.Mode)
			if err != nil {
				return errResult(err.Error()), nil
			}
			created, err := svc.Create(ctx, c, transfer.CreateParams{
				SessionID: args.SessionID, Direction: args.Direction, Path: args.Path,
				MaxBytes: args.MaxBytes, SHA256: args.SHA256, Overwrite: args.Overwrite, Mode: mode,
			})
			if err != nil {
				return errResult(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"transferId": created.TransferID, "url": created.URL, "method": created.Method,
				"expiresAt": created.ExpiresAt.UTC().Format(clock.ISOMillis),
				"maxBytes":  created.MaxBytes, "command": created.Command,
			})
		case "status", "cancel":
			if args.TransferID == "" {
				return errResult("transferId is required"), nil
			}
			op := svc.Status
			if args.Action == "cancel" {
				op = svc.Cancel
			}
			v, err := op(ctx, c, args.TransferID)
			if err != nil {
				return errResult(err.Error()), nil
			}
			return jsonResult(v.StatusResult())
		}
		return errResult("unknown action: " + args.Action), nil
	})
}
