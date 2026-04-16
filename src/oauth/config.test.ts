import { describe, it, expect } from "vitest";
import { OAuthConfigSchema, defaultOAuthConfig } from "./config.js";

describe("OAuthConfigSchema", () => {
  it("applies defaults for an empty object", () => {
    const parsed = OAuthConfigSchema.parse({});
    expect(parsed.scopes).toEqual(["mcp", "agent"]);
    expect(parsed.dynamicClientRegistration).toBe("open");
    expect(parsed.accessTokenTtlSeconds).toBe(3600);
    expect(parsed.refreshTokenTtlSeconds).toBe(60 * 60 * 24 * 30);
    expect(parsed.authorizationCodeTtlSeconds).toBe(60);
    expect(parsed.resourceIndicators).toEqual(["${issuer}/mcp", "${issuer}/agent-proxy"]);
    expect(parsed.signingKeyRotationDays).toBe(90);
    expect(parsed.signingKeyOverlapDays).toBe(30);
    expect(parsed.registrationRateLimitPerMinute).toBe(10);
  });

  it("exposes defaultOAuthConfig matching schema defaults", () => {
    expect(defaultOAuthConfig).toEqual(OAuthConfigSchema.parse({}));
  });

  it("accepts user overrides", () => {
    const parsed = OAuthConfigSchema.parse({
      scopes: ["mcp"],
      dynamicClientRegistration: "disabled",
      accessTokenTtlSeconds: 900,
    });
    expect(parsed.scopes).toEqual(["mcp"]);
    expect(parsed.dynamicClientRegistration).toBe("disabled");
    expect(parsed.accessTokenTtlSeconds).toBe(900);
  });

  it("rejects admin-only DCR (not implemented in Phase 1)", () => {
    // admin-only is documented as a future mode; narrowing the enum
    // ensures operators who try it get an explicit parse failure rather
    // than silent "open" behaviour.
    expect(() => OAuthConfigSchema.parse({ dynamicClientRegistration: "admin-only" })).toThrow();
  });

  it("rejects unknown keys (strict mode)", () => {
    expect(() => OAuthConfigSchema.parse({ unknownField: true })).toThrow();
  });

  it("rejects non-positive TTLs", () => {
    expect(() => OAuthConfigSchema.parse({ accessTokenTtlSeconds: 0 })).toThrow();
    expect(() => OAuthConfigSchema.parse({ refreshTokenTtlSeconds: -1 })).toThrow();
  });

  it("rejects empty scope strings", () => {
    expect(() => OAuthConfigSchema.parse({ scopes: [""] })).toThrow();
  });

  it("rejects invalid DCR mode", () => {
    expect(() => OAuthConfigSchema.parse({ dynamicClientRegistration: "yolo" })).toThrow();
  });

  it("rejects signing key overlap >= rotation", () => {
    expect(() =>
      OAuthConfigSchema.parse({ signingKeyRotationDays: 30, signingKeyOverlapDays: 30 }),
    ).toThrow(/signingKeyOverlapDays must be less than signingKeyRotationDays/);
    expect(() =>
      OAuthConfigSchema.parse({ signingKeyRotationDays: 30, signingKeyOverlapDays: 60 }),
    ).toThrow(/signingKeyOverlapDays must be less than signingKeyRotationDays/);
  });

  it("accepts overlap < rotation", () => {
    const parsed = OAuthConfigSchema.parse({
      signingKeyRotationDays: 30,
      signingKeyOverlapDays: 7,
    });
    expect(parsed.signingKeyRotationDays).toBe(30);
    expect(parsed.signingKeyOverlapDays).toBe(7);
  });
});
