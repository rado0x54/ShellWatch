// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Phase 0 spike (#210): the official MCP go-sdk serving one tool over the
// streamable HTTP transport, exercised end-to-end with the SDK's client —
// the transport/session model the Go backend's /mcp surface will use.
package spike

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoArgs struct {
	Text string `json:"text" jsonschema:"the text to echo back"`
}

type echoResult struct {
	Echo string `json:"echo"`
}

func TestMcpStreamableHTTPOneTool(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "shellwatch-spike", Version: "0.0.1"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "spike_echo",
		Description: "Echo the input back (Phase 0 transport smoke test)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, echoResult, error) {
		return nil, echoResult{Echo: in.Text}, nil
	})

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "spike-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "spike_echo" {
		t.Fatalf("unexpected tools: %+v", tools.Tools)
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "spike_echo",
		Arguments: map[string]any{"text": "phase-0"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %+v", res.Content)
	}
	out, ok := res.StructuredContent.(map[string]any)
	if !ok || out["echo"] != "phase-0" {
		t.Fatalf("unexpected structured content: %#v", res.StructuredContent)
	}
	t.Log("MCP go-sdk streamable HTTP round-trip OK (per-session state, one tool)")
}
