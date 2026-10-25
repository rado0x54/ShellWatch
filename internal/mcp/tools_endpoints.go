// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Endpoint + key management tools (port of src/mcp/tools/endpoints.ts, keys.ts).
// manage_endpoints list omits userVerification/agentForward/isDemo (contract
// item C); read returns the full row. create requires a caller-supplied id
// (item C — opposite of REST). create/update accept userVerification and
// agentForward — full endpoint editability via MCP is the contract
// (docs/api/mcp-tools.md); Node's zod schema stripped them until the same
// change landed there.
package mcp

import (
	"context"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/store"
)

const demoReadOnlyErr = "Demo endpoints are read-only"

// endpointPatchFromWire converts the tool's raw data object into a typed
// patch, validating field types, the userVerification enum, and the
// description cap (the zod-equivalent layer; Node validates in the tool
// schema). Returns a non-empty message when a field is invalid.
func endpointPatchFromWire(data map[string]any) (agent.EndpointPatch, string) {
	var p agent.EndpointPatch
	strField := func(key string, dst **string) string {
		v, ok := data[key]
		if !ok {
			return ""
		}
		s, isStr := v.(string)
		if !isStr {
			return "data." + key + " must be a string"
		}
		*dst = &s
		return ""
	}
	if msg := strField("label", &p.Label); msg != "" {
		return p, msg
	}
	if msg := strField("host", &p.Host); msg != "" {
		return p, msg
	}
	if msg := strField("username", &p.Username); msg != "" {
		return p, msg
	}
	if v, ok := data["port"]; ok {
		n, isNum := v.(float64) // JSON numbers decode as float64
		if !isNum {
			return p, "data.port must be a number"
		}
		port := int64(n)
		p.Port = &port
	}
	if v, ok := data["userVerification"]; ok {
		s, isStr := v.(string)
		if !isStr || !endpointsvc.IsUserVerification(s) {
			return p, "data.userVerification must be one of: " + strings.Join(endpointsvc.UserVerificationValues, ", ")
		}
		p.UserVerification = &s
	}
	if v, ok := data["agentForward"]; ok {
		b, isBool := v.(bool)
		if !isBool {
			return p, "data.agentForward must be a boolean"
		}
		p.AgentForward = &b
	}
	if v, present := data["description"]; present {
		p.DescriptionSet = true
		if v != nil {
			s, isStr := v.(string)
			if !isStr || len(s) > endpointsvc.DescriptionMaxLen {
				return p, "data.description must be a string up to 1000 characters (pass null to clear)"
			}
			p.Description = &s
		}
	}
	return p, ""
}

func strOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func registerEndpointTools(srv *mcpsdk.Server, as *agent.Session) {
	srv.AddTool(&mcpsdk.Tool{
		Name:        "shellwatch_manage_endpoints",
		Description: "Manage SSH endpoints. Actions: list, read, create, update, delete.",
		InputSchema: objSchema(map[string]any{
			"action": map[string]any{"type": "string", "enum": []string{"list", "read", "create", "update", "delete"}},
			"id":     map[string]any{"type": "string"},
			"data": map[string]any{
				"type":        "object",
				"description": "Endpoint fields (for create and update)",
				"properties": map[string]any{
					"label":    map[string]any{"type": "string"},
					"host":     map[string]any{"type": "string"},
					"port":     map[string]any{"type": "number"},
					"username": map[string]any{"type": "string"},
					"userVerification": map[string]any{
						"type": "string", "enum": endpointsvc.UserVerificationValues,
						"description": "WebAuthn user-verification policy for passkey signing (create default: required)",
					},
					"agentForward": map[string]any{
						"type":        "boolean",
						"description": "Offer SSH agent forwarding to the remote host (create default: true)",
					},
					"description": map[string]any{
						"type":        []string{"string", "null"},
						"description": "Free-form context (max 1000 chars) shown to agents on connect. Pass null to clear.",
					},
				},
			},
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
			patch, msg := endpointPatchFromWire(args.Data)
			if msg != "" {
				return errResult(msg), nil
			}
			if args.ID == "" || strOrEmpty(patch.Label) == "" || strOrEmpty(patch.Host) == "" || strOrEmpty(patch.Username) == "" {
				return errResult("id, data.label, data.host, data.username are required"), nil
			}
			// Defaults match the Node repo (endpoint-repo.ts create):
			// userVerification "required", agentForward true, port 22.
			ep := store.Endpoint{
				ID: args.ID, Label: *patch.Label, Host: *patch.Host, Port: 22,
				Username: *patch.Username, UserVerification: "required", AgentForward: true,
				Description: patch.Description,
			}
			if patch.Port != nil {
				ep.Port = *patch.Port
			}
			if patch.UserVerification != nil {
				ep.UserVerification = *patch.UserVerification
			}
			if patch.AgentForward != nil {
				ep.AgentForward = *patch.AgentForward
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
			patch, msg := endpointPatchFromWire(args.Data)
			if msg != "" {
				return errResult(msg), nil
			}
			ok, err := as.UpdateEndpoint(ctx, args.ID, patch)
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
