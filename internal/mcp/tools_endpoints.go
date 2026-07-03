// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Endpoint + key management tools (port of src/mcp/tools/endpoints.ts, keys.ts).
// manage_endpoints list omits userVerification/agentForward/isDemo (contract
// item C); read returns the full row. create requires a caller-supplied id
// (item C — opposite of REST).
package mcp

import (
	"context"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/store"
)

const demoReadOnlyErr = "Demo endpoints are read-only"

func registerEndpointTools(srv *mcpsdk.Server, as *agent.Session) {
	srv.AddTool(&mcpsdk.Tool{
		Name:        "shellwatch_manage_endpoints",
		Description: "Manage SSH endpoints. Actions: list, read, create, update, delete.",
		InputSchema: objSchema(map[string]any{
			"action": map[string]any{"type": "string", "enum": []string{"list", "read", "create", "update", "delete"}},
			"id":     map[string]any{"type": "string"},
			"data":   map[string]any{"type": "object"},
		}, "action"),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		var args struct {
			Action string         `json:"action"`
			ID     string         `json:"id"`
			Data   map[string]any `json:"data"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult(err.Error()), nil
		}
		switch args.Action {
		case "list":
			eps, err := as.ListEndpoints(ctx)
			if err != nil {
				return errResult(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(eps))
			for _, e := range eps {
				out = append(out, map[string]any{
					"id": e.ID, "label": e.Label, "host": e.Host, "port": e.Port,
					"username": e.Username, "description": e.Description,
				})
			}
			return jsonResult(map[string]any{"endpoints": out})
		case "read":
			if args.ID == "" {
				return errResult("id is required"), nil
			}
			ep, err := as.GetEndpoint(ctx, args.ID)
			if err != nil {
				return errResult(err.Error()), nil
			}
			if ep == nil {
				return errResult("Endpoint not found: " + args.ID), nil
			}
			return jsonResult(endpointFull(*ep))
		case "create":
			if demo.IsID(args.ID) {
				return errResult(demoReadOnlyErr), nil
			}
			label, _ := args.Data["label"].(string)
			host, _ := args.Data["host"].(string)
			username, _ := args.Data["username"].(string)
			if args.ID == "" || label == "" || host == "" || username == "" {
				return errResult("id, data.label, data.host, data.username are required"), nil
			}
			port := int64(22)
			if p, ok := args.Data["port"].(float64); ok {
				port = int64(p)
			}
			var desc *string
			if d, ok := args.Data["description"].(string); ok {
				desc = &d
			}
			ep := store.Endpoint{
				ID: args.ID, Label: label, Host: host, Port: port, Username: username,
				UserVerification: "required", Description: desc,
			}
			if err := as.CreateEndpoint(ctx, ep); err != nil {
				return errResult(err.Error()), nil
			}
			return jsonResult(map[string]any{"status": "created", "id": args.ID})
		case "update":
			if demo.IsID(args.ID) {
				return errResult(demoReadOnlyErr), nil
			}
			if args.ID == "" || args.Data == nil {
				return errResult("id and data are required"), nil
			}
			ok, err := as.UpdateEndpoint(ctx, args.ID, args.Data)
			if err != nil {
				return errResult(err.Error()), nil
			}
			if !ok {
				return errResult("Endpoint not found: " + args.ID), nil
			}
			return jsonResult(map[string]any{"status": "updated", "id": args.ID})
		case "delete":
			if demo.IsID(args.ID) {
				return errResult(demoReadOnlyErr), nil
			}
			if args.ID == "" {
				return errResult("id is required"), nil
			}
			ok, err := as.DeleteEndpoint(ctx, args.ID)
			if err != nil {
				return errResult(err.Error()), nil
			}
			if !ok {
				return errResult("Endpoint not found: " + args.ID), nil
			}
			return jsonResult(map[string]any{"status": "deleted", "id": args.ID})
		}
		return errResult("unknown action: " + args.Action), nil
	})
}

func endpointFull(e store.Endpoint) map[string]any {
	return map[string]any{
		"id": e.ID, "accountId": e.AccountID, "label": e.Label, "host": e.Host, "port": e.Port,
		"username": e.Username, "userVerification": e.UserVerification,
		"agentForward": e.AgentForward, "description": e.Description,
	}
}

func registerKeyTools(srv *mcpsdk.Server, _ *agent.Session, keys *store.SSHKeys) {
	srv.AddTool(&mcpsdk.Tool{
		Name:        "shellwatch_manage_keys",
		Description: "Manage SSH keys. Keys are auto-discovered from the key directory. Actions: list, read.",
		InputSchema: objSchema(map[string]any{
			"action": map[string]any{"type": "string", "enum": []string{"list", "read"}},
			"id":     map[string]any{"type": "string"},
		}, "action"),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		var args struct {
			Action string `json:"action"`
			ID     string `json:"id"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult(err.Error()), nil
		}
		switch args.Action {
		case "list":
			ks, err := keys.List(ctx)
			if err != nil {
				return errResult(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(ks))
			for _, k := range ks {
				out = append(out, map[string]any{"id": k.ID, "label": k.Label, "type": k.Type, "fingerprint": k.Fingerprint})
			}
			return jsonResult(map[string]any{"keys": out})
		case "read":
			if args.ID == "" {
				return errResult("id is required"), nil
			}
			k, err := keys.Get(ctx, args.ID)
			if err != nil {
				return errResult(err.Error()), nil
			}
			if k == nil {
				return errResult("Key not found: " + args.ID), nil
			}
			return jsonResult(map[string]any{
				"id": k.ID, "label": k.Label, "type": k.Type, "fingerprint": k.Fingerprint, "publicKey": k.PublicKey,
			})
		}
		return errResult("unknown action: " + args.Action), nil
	})
}
