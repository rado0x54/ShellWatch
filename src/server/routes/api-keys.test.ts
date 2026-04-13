import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { InMemoryApiKeyRepository } from "../../db/repositories/api-key-repo.js";
import { registerApiKeyRoutes } from "./api-keys.js";

async function buildApp() {
  const app = Fastify();
  const apiKeyRepo = new InMemoryApiKeyRepository();
  app.addHook("onRequest", async (request) => {
    request.accountId = "acct-test";
  });
  registerApiKeyRoutes({ app, apiKeyRepo });
  return { app, apiKeyRepo };
}

describe("POST /api/keys/api scope validation", () => {
  it("defaults to ['mcp'] when scopes is omitted", async () => {
    const { app } = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/api/keys/api",
      payload: { label: "default" },
    });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).scopes).toEqual(["mcp"]);
    await app.close();
  });

  it("accepts valid scopes and dedupes", async () => {
    const { app } = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/api/keys/api",
      payload: { label: "agent-key", scopes: ["agent", "mcp", "agent"] },
    });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.scopes.sort()).toEqual(["agent", "mcp"]);
    await app.close();
  });

  it("rejects empty scopes array with 400", async () => {
    const { app } = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/api/keys/api",
      payload: { label: "empty", scopes: [] },
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/scopes/i);
    await app.close();
  });

  it("rejects unknown scope values with 400", async () => {
    const { app } = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/api/keys/api",
      payload: { label: "bogus", scopes: ["bogus"] },
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/scopes/i);
    await app.close();
  });

  it("rejects non-array scopes with 400", async () => {
    const { app } = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/api/keys/api",
      payload: { label: "bad", scopes: "agent" },
    });
    expect(res.statusCode).toBe(400);
    await app.close();
  });
});
