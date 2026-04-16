import type Provider from "oidc-provider";
import { describe, expect, it, vi } from "vitest";
import { createOAuthTokenVerifier } from "./verifier.js";

/**
 * Verifier tests stub `provider.AccessToken.find` directly — the token
 * lookup path is already exercised by the Drizzle adapter tests, so here
 * we only need to check the thin mapping from panva's AccessToken record
 * to `Principal` plus the audience-binding rejection.
 */
function makeProvider(accessToken: Partial<Record<string, unknown>> | null): Provider {
  return {
    AccessToken: {
      find: vi.fn(async () => (accessToken ? accessToken : undefined)),
    },
  } as unknown as Provider;
}

function expectedResource() {
  return "https://host.example/mcp";
}

describe("createOAuthTokenVerifier", () => {
  it("maps a valid access token with matching audience to a Principal", async () => {
    const provider = makeProvider({
      jti: "tok_1",
      accountId: "acct_9",
      scopes: new Set(["mcp", "agent"]),
      clientId: "dcr-client-abc",
      aud: "https://host.example/mcp",
      exp: 1_800_000_000,
      isExpired: false,
    });

    const verifier = createOAuthTokenVerifier(provider, { expectedResource });
    expect(await verifier.verify("opaque-token")).toEqual({
      accountId: "acct_9",
      scopes: ["mcp", "agent"],
      source: "oauth",
      clientId: "dcr-client-abc",
      tokenId: "tok_1",
      expiresAt: new Date(1_800_000_000 * 1000),
    });
  });

  it("returns null for an expired token", async () => {
    const provider = makeProvider({
      jti: "tok_2",
      accountId: "acct_9",
      scopes: new Set(["mcp"]),
      aud: "https://host.example/mcp",
      exp: 1_000_000,
      isExpired: true,
    });
    const verifier = createOAuthTokenVerifier(provider, { expectedResource });
    expect(await verifier.verify("opaque-token")).toBeNull();
  });

  it("returns null when panva has no record for the token", async () => {
    const verifier = createOAuthTokenVerifier(makeProvider(null), { expectedResource });
    expect(await verifier.verify("nonexistent")).toBeNull();
  });

  it("rejects a token whose audience does not match the expected resource (RFC 8707)", async () => {
    const provider = makeProvider({
      jti: "tok_3",
      accountId: "acct_1",
      scopes: new Set(["mcp"]),
      aud: "https://host.example/agent-proxy",
      isExpired: false,
    });
    const verifier = createOAuthTokenVerifier(provider, { expectedResource });
    expect(await verifier.verify("opaque-token")).toBeNull();
  });

  it("accepts a token whose audience array contains the expected resource", async () => {
    const provider = makeProvider({
      jti: "tok_4",
      accountId: "acct_1",
      scopes: new Set(["mcp"]),
      aud: ["https://other.example/api", "https://host.example/mcp"],
      isExpired: false,
    });
    const verifier = createOAuthTokenVerifier(provider, { expectedResource });
    const principal = await verifier.verify("opaque-token");
    expect(principal).not.toBeNull();
    expect(principal?.accountId).toBe("acct_1");
  });

  it("rejects a token with no audience claim", async () => {
    const provider = makeProvider({
      jti: "tok_5",
      accountId: "acct_1",
      scopes: new Set(["mcp"]),
      isExpired: false,
    });
    const verifier = createOAuthTokenVerifier(provider, { expectedResource });
    expect(await verifier.verify("opaque-token")).toBeNull();
  });

  it("rejects a token with no accountId (no resolvable identity)", async () => {
    const provider = makeProvider({
      jti: "tok_6",
      // accountId intentionally missing — e.g. a hypothetical
      // client_credentials-minted token.
      scopes: new Set(["mcp"]),
      aud: "https://host.example/mcp",
      isExpired: false,
    });
    const verifier = createOAuthTokenVerifier(provider, { expectedResource });
    expect(await verifier.verify("opaque-token")).toBeNull();
  });

  it("returns null for an empty bearer", async () => {
    const verifier = createOAuthTokenVerifier(makeProvider(null), { expectedResource });
    expect(await verifier.verify("")).toBeNull();
  });
});
