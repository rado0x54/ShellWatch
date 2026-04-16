import type { FastifyRequest } from "fastify";
import { describe, expect, it } from "vitest";
import { extractApiKey, extractOAuthBearer } from "./extract-credentials.js";

function fakeReq(headers: Record<string, string | string[] | undefined>): FastifyRequest {
  return { headers } as unknown as FastifyRequest;
}

describe("extractOAuthBearer", () => {
  it("reads non-sw_ bearer tokens from the Authorization header", () => {
    const req = fakeReq({ authorization: "Bearer opaque-token-abc" });
    expect(extractOAuthBearer(req)).toBe("opaque-token-abc");
  });

  it("ignores Authorization: Bearer sw_… (routes to api-key verifier instead)", () => {
    const req = fakeReq({ authorization: "Bearer sw_abc123" });
    expect(extractOAuthBearer(req)).toBeNull();
  });

  it("reads the sw_session cookie", () => {
    const req = fakeReq({ cookie: "sw_session=oauth-opaque-xyz; other=value" });
    expect(extractOAuthBearer(req)).toBe("oauth-opaque-xyz");
  });

  it("prefers Authorization header over cookie when both present", () => {
    const req = fakeReq({
      authorization: "Bearer header-token",
      cookie: "sw_session=cookie-token",
    });
    expect(extractOAuthBearer(req)).toBe("header-token");
  });

  it("returns null when neither source is present", () => {
    expect(extractOAuthBearer(fakeReq({}))).toBeNull();
  });

  it("returns null when Authorization is not a Bearer scheme", () => {
    const req = fakeReq({ authorization: "Basic dXNlcjpwYXNz" });
    expect(extractOAuthBearer(req)).toBeNull();
  });

  it("url-decodes cookie values", () => {
    const req = fakeReq({ cookie: "sw_session=token%20with%20spaces" });
    expect(extractOAuthBearer(req)).toBe("token with spaces");
  });
});

describe("extractApiKey", () => {
  it("reads X-API-Key header", () => {
    const req = fakeReq({ "x-api-key": "sw_abc123" });
    expect(extractApiKey(req)).toBe("sw_abc123");
  });

  it("accepts legacy Authorization: Bearer sw_… for backward compatibility", () => {
    const req = fakeReq({ authorization: "Bearer sw_legacy" });
    expect(extractApiKey(req)).toBe("sw_legacy");
  });

  it("does not pick up non-sw_ bearer tokens (those go to oauth)", () => {
    const req = fakeReq({ authorization: "Bearer opaque-oauth-token" });
    expect(extractApiKey(req)).toBeNull();
  });

  it("prefers X-API-Key when both header and Authorization are present", () => {
    const req = fakeReq({
      "x-api-key": "sw_primary",
      authorization: "Bearer sw_legacy",
    });
    expect(extractApiKey(req)).toBe("sw_primary");
  });

  it("handles X-API-Key delivered as an array", () => {
    const req = fakeReq({ "x-api-key": ["sw_first", "sw_second"] });
    expect(extractApiKey(req)).toBe("sw_first");
  });

  it("returns null when no credentials are present", () => {
    expect(extractApiKey(fakeReq({}))).toBeNull();
  });
});
