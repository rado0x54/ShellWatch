// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Session tools (port of src/mcp/tools/sessions.ts).
package mcp

import (
	"context"
	"strings"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
)

func objSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func registerSessionTools(srv *mcpsdk.Server, as *agent.Session) {
	srv.AddTool(&mcpsdk.Tool{
		Name:        "shellwatch_create_session",
		Description: "Create a new terminal session for a configured endpoint. The reason parameter is required and shown to the human approver in the passkey-tap UI.",
		InputSchema: objSchema(map[string]any{
			"endpointId": map[string]any{"type": "string", "description": "ID of the endpoint to connect to"},
			"reason":     map[string]any{"type": "string", "description": "Why this session is being created. Shown to the human approver."},
		}, "endpointId", "reason"),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		var args struct {
			EndpointID string `json:"endpointId"`
			Reason     string `json:"reason"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult(err.Error()), nil
		}
		captureClientInfo(as, req)
		reason := strings.TrimSpace(args.Reason)
		if reason == "" {
			return errResult("reason must not be empty"), nil
		}
		sess, err := as.CreateSession(ctx, args.EndpointID, reason)
		if err != nil {
			return errResult(err.Error()), nil
		}
		return jsonResult(map[string]any{
			"sessionId": sess.SessionID, "endpointId": sess.EndpointID, "status": string(sess.Status),
		})
	})

	srv.AddTool(&mcpsdk.Tool{
		Name:        "shellwatch_list_sessions",
		Description: "List your active terminal sessions",
		InputSchema: objSchema(map[string]any{}),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		list := as.ListSessions()
		sessions := make([]map[string]any, 0, len(list))
		for _, s := range list {
			sessions = append(sessions, map[string]any{
				"sessionId": s.SessionID, "endpointId": s.EndpointID, "status": string(s.Status),
				"createdAt": s.CreatedAt.UTC().Format(isoMillis),
			})
		}
		return jsonResult(map[string]any{"sessions": sessions})
	})

	srv.AddTool(&mcpsdk.Tool{
		Name:        "shellwatch_send_keys",
		Description: "Send named keystrokes or text to a terminal session. Use text:<content> for arbitrary text.",
		InputSchema: objSchema(map[string]any{
			"sessionId": map[string]any{"type": "string"},
			"keys":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "sessionId", "keys"),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		var args struct {
			SessionID string   `json:"sessionId"`
			Keys      []string `json:"keys"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult(err.Error()), nil
		}
		if err := as.SendKeys(args.SessionID, args.Keys); err != nil {
			return errResult(err.Error()), nil
		}
		return jsonResult(map[string]any{"status": "sent", "keys": args.Keys})
	})

	srv.AddTool(&mcpsdk.Tool{
		Name:        "shellwatch_read_output",
		Description: "Read terminal output from a session. Use afterOffset for incremental reads. Set waitMs to long-poll: the call returns as soon as output past afterOffset exists (or the wait elapses), so you never busy-poll.",
		InputSchema: objSchema(map[string]any{
			"sessionId":   map[string]any{"type": "string"},
			"afterOffset": map[string]any{"type": "number"},
			"limit":       map[string]any{"type": "number"},
			"waitMs":      map[string]any{"type": "number", "description": "Max milliseconds to wait for new output past afterOffset (0-30000, default 0 = return immediately)."},
		}, "sessionId"),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		var args struct {
			SessionID   string `json:"sessionId"`
			AfterOffset int64  `json:"afterOffset"`
			Limit       int    `json:"limit"`
			WaitMs      int64  `json:"waitMs"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult(err.Error()), nil
		}
		if args.WaitMs < 0 || args.WaitMs > 30000 {
			return errResult("waitMs must be between 0 and 30000"), nil
		}
		res, err := as.ReadOutput(ctx, agent.ReadOutputParams{
			SessionID:   args.SessionID,
			AfterOffset: args.AfterOffset,
			Limit:       args.Limit,
			Wait:        time.Duration(args.WaitMs) * time.Millisecond,
		})
		if err != nil {
			return errResult(err.Error()), nil
		}
		return jsonResult(map[string]any{
			"data": string(res.Data), "offset": res.Offset, "hasMore": res.HasMore,
		})
	})

	srv.AddTool(&mcpsdk.Tool{
		Name:        "shellwatch_close_session",
		Description: "Close a terminal session and release resources",
		InputSchema: objSchema(map[string]any{"sessionId": map[string]any{"type": "string"}}, "sessionId"),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		var args struct {
			SessionID string `json:"sessionId"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult(err.Error()), nil
		}
		if err := as.CloseSession(args.SessionID); err != nil {
			return errResult(err.Error()), nil
		}
		return jsonResult(map[string]any{"status": "closed"})
	})
}
