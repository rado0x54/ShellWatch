// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// OAuth client registration log store (#242): query building, the admin 403
// path, and how a row identifies itself in the list.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fetchOAuthClients,
  displayIdentity,
  NotAdminError,
  type OAuthClientRegistration,
} from "./oauth-clients.js";

function row(over: Partial<OAuthClientRegistration> = {}): OAuthClientRegistration {
  return {
    id: "ocr_1",
    clientId: "https://apps.example.com/.well-known/client.json",
    origin: "cimd",
    event: "registered",
    clientName: "Example MCP Client",
    metadataHost: "apps.example.com",
    authMethod: "none",
    redirectUris: ["http://127.0.0.1/callback"],
    scope: "mcp offline_access",
    reason: null,
    sourceIp: "203.0.113.2",
    createdAt: "2026-01-01T00:00:00.000Z",
    ...over,
  };
}

describe("fetchOAuthClients", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("requests the log with a default limit and no empty filters", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ rows: [], nextCursor: null })));

    const page = await fetchOAuthClients();

    expect(page).toEqual({ rows: [], nextCursor: null });
    expect(fetchSpy.mock.calls[0][0]).toBe("/api/audit/oauth-clients?limit=50");
  });

  it("passes filters and the cursor through", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ rows: [], nextCursor: null })));

    await fetchOAuthClients(
      { origin: "cimd", event: "rejected", clientId: "https://a.example/c.json" },
      "cursor-1",
      10,
    );

    const url = String(fetchSpy.mock.calls[0][0]);
    const params = new URL(url, "http://localhost").searchParams;
    expect(params.get("origin")).toBe("cimd");
    expect(params.get("event")).toBe("rejected");
    expect(params.get("clientId")).toBe("https://a.example/c.json");
    expect(params.get("cursor")).toBe("cursor-1");
    expect(params.get("limit")).toBe("10");
  });

  // The whole surface is admin-only, so 403 is an expected outcome the page
  // explains rather than an error to toast.
  it("raises NotAdminError on 403", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "Admin role required" }), { status: 403 }),
    );
    await expect(fetchOAuthClients()).rejects.toBeInstanceOf(NotAdminError);
  });

  it("surfaces the server's error message on other failures", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "invalid origin filter" }), { status: 400 }),
    );
    await expect(fetchOAuthClients({ origin: "bogus" })).rejects.toThrow("invalid origin filter");
  });

  it("falls back to a generic message when the body is not JSON", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response("<html>502</html>", { status: 502, statusText: "Bad Gateway" }),
    );
    await expect(fetchOAuthClients()).rejects.toThrow(/Bad Gateway|Failed to fetch/);
  });
});

describe("displayIdentity", () => {
  // For CIMD the hostname is the identity cue the spec wants surfaced
  // (draft-02 §9.1): it is the part of a URL client_id an attacker cannot
  // choose freely, unlike client_name.
  it("prefers the document host for CIMD", () => {
    expect(displayIdentity(row())).toBe("apps.example.com");
    expect(displayIdentity(row({ clientName: "Totally Legit Bank" }))).toBe("apps.example.com");
  });

  it("falls back to the client name for DCR, which has no document", () => {
    expect(
      displayIdentity(row({ origin: "dcr", metadataHost: null, clientName: "MCP Inspector" })),
    ).toBe("MCP Inspector");
  });

  it("falls back to the client id, then a placeholder", () => {
    expect(
      displayIdentity(
        row({ origin: "dcr", metadataHost: null, clientName: null, clientId: "u-1" }),
      ),
    ).toBe("u-1");
    // A rejection has neither a name nor a client id.
    expect(
      displayIdentity(row({ origin: "dcr", metadataHost: null, clientName: null, clientId: "" })),
    ).toBe("unknown client");
  });
});
