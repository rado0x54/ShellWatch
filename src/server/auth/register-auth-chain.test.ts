import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { registerAuthChain } from "./register-auth-chain.js";
import type { Principal, TokenVerifier } from "./token-verifier.js";

function staticVerifier(accepts: Record<string, Principal | null>): TokenVerifier {
  return {
    async verify(bearer: string) {
      return accepts[bearer] ?? null;
    },
  };
}

const apiKeyAccepts: Record<string, Principal> = {
  sw_valid: {
    accountId: "acct_1",
    scopes: ["mcp"],
    source: "api-key",
    tokenId: "k1",
  },
};

const oauthAccepts: Record<string, Principal> = {
  "opaque-ok": {
    accountId: "acct_2",
    scopes: ["mcp"],
    source: "oauth",
    clientId: "dcr-1",
    tokenId: "t1",
  },
};

async function buildApp(oauthEnabled: boolean): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  registerAuthChain({
    app,
    protectedPath: "/mcp",
    apiKeyVerifier: staticVerifier(apiKeyAccepts),
    oauthVerifier: oauthEnabled ? staticVerifier(oauthAccepts) : undefined,
    resourceMetadataUrl: oauthEnabled
      ? "https://host.example/.well-known/oauth-protected-resource"
      : undefined,
  });
  app.get("/mcp/resource", async (req) => ({
    accountId: req.principal?.accountId,
    source: req.principal?.source,
  }));
  app.get("/public", async () => ({ ok: true }));
  await app.ready();
  return app;
}

describe("registerAuthChain", () => {
  let app: FastifyInstance;

  afterEach(async () => {
    await app.close();
  });

  describe("with OAuth enabled", () => {
    beforeEach(async () => {
      app = await buildApp(true);
    });

    it("accepts API key via X-API-Key header", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/mcp/resource",
        headers: { "x-api-key": "sw_valid" },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ accountId: "acct_1", source: "api-key" });
    });

    it("accepts API key via legacy Authorization Bearer sw_...", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/mcp/resource",
        headers: { authorization: "Bearer sw_valid" },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ accountId: "acct_1", source: "api-key" });
    });

    it("accepts OAuth bearer token via Authorization header", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/mcp/resource",
        headers: { authorization: "Bearer opaque-ok" },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ accountId: "acct_2", source: "oauth" });
    });

    it("accepts OAuth token via sw_session cookie", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/mcp/resource",
        headers: { cookie: "sw_session=opaque-ok" },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ accountId: "acct_2", source: "oauth" });
    });

    it("rejects unauthenticated requests with 401 + WWW-Authenticate", async () => {
      const res = await app.inject({ method: "GET", url: "/mcp/resource" });
      expect(res.statusCode).toBe(401);
      expect(res.headers["www-authenticate"]).toBe(
        'Bearer realm="shellwatch", resource_metadata="https://host.example/.well-known/oauth-protected-resource"',
      );
    });

    it("rejects invalid API key with 401", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/mcp/resource",
        headers: { "x-api-key": "sw_does_not_exist" },
      });
      expect(res.statusCode).toBe(401);
    });

    it("rejects invalid OAuth bearer with 401", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/mcp/resource",
        headers: { authorization: "Bearer wrong-token" },
      });
      expect(res.statusCode).toBe(401);
    });

    it("does not intercept non-/mcp paths", async () => {
      const res = await app.inject({ method: "GET", url: "/public" });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ ok: true });
    });

    it("does not intercept sibling paths sharing the prefix (e.g. /mcpevil)", async () => {
      // Sibling route would be caught by a naive `startsWith("/mcp")`
      // check; it must resolve without the auth hook firing (no 401,
      // no WWW-Authenticate header). Builds a fresh app because routes
      // can't be added after `ready()`.
      const siblingApp = Fastify({ logger: false });
      registerAuthChain({
        app: siblingApp,
        protectedPath: "/mcp",
        apiKeyVerifier: staticVerifier(apiKeyAccepts),
      });
      siblingApp.get("/mcpevil/public", async () => ({ ok: "sibling" }));
      await siblingApp.ready();
      try {
        const res = await siblingApp.inject({ method: "GET", url: "/mcpevil/public" });
        expect(res.statusCode).toBe(200);
        expect(res.headers["www-authenticate"]).toBeUndefined();
        expect(res.json()).toEqual({ ok: "sibling" });
      } finally {
        await siblingApp.close();
      }
    });
  });

  describe("with OAuth disabled", () => {
    beforeEach(async () => {
      app = await buildApp(false);
    });

    it("still authenticates API-key clients", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/mcp/resource",
        headers: { authorization: "Bearer sw_valid" },
      });
      expect(res.statusCode).toBe(200);
    });

    it("returns legacy 401 message without WWW-Authenticate metadata pointer", async () => {
      const res = await app.inject({ method: "GET", url: "/mcp/resource" });
      expect(res.statusCode).toBe(401);
      expect(res.headers["www-authenticate"]).toBeUndefined();
      expect(res.json()).toEqual({
        error: "API key required. Use Authorization: Bearer sw_...",
      });
    });

    it("rejects OAuth-looking bearers (no OAuth verifier in chain)", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/mcp/resource",
        headers: { authorization: "Bearer opaque-ok" },
      });
      expect(res.statusCode).toBe(401);
    });
  });
});
