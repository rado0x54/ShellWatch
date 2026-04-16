import Fastify from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { registerProtectedResourceMetadata } from "./well-known.js";

describe("registerProtectedResourceMetadata", () => {
  let close: (() => Promise<void>) | null = null;

  afterEach(async () => {
    if (close) {
      await close();
      close = null;
    }
  });

  it("serves an RFC 9728 document pointing at our AS", async () => {
    const app = Fastify({ logger: false });
    registerProtectedResourceMetadata({
      app,
      baseUrl: "https://host.example",
      scopes: ["mcp", "agent"],
    });
    close = () => app.close();
    await app.ready();

    const res = await app.inject({
      method: "GET",
      url: "/.well-known/oauth-protected-resource",
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toMatch(/application\/json/);

    const body = res.json<Record<string, unknown>>();
    expect(body).toEqual({
      resource: "https://host.example/mcp",
      resources: ["https://host.example/mcp"],
      authorization_servers: ["https://host.example/oidc"],
      scopes_supported: ["mcp", "agent"],
      bearer_methods_supported: ["header"],
    });
  });

  it("advertises multiple resources when configured", async () => {
    const app = Fastify({ logger: false });
    registerProtectedResourceMetadata({
      app,
      baseUrl: "https://host.example",
      scopes: ["mcp", "agent"],
      resources: ["/mcp", "/agent-proxy"],
    });
    close = () => app.close();
    await app.ready();

    const res = await app.inject({
      method: "GET",
      url: "/.well-known/oauth-protected-resource",
    });
    const body = res.json<Record<string, unknown>>();
    expect(body.resource).toBe("https://host.example/mcp");
    expect(body.resources).toEqual([
      "https://host.example/mcp",
      "https://host.example/agent-proxy",
    ]);
  });
});
