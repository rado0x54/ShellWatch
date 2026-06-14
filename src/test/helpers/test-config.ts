// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { type Config, securityFieldDefaults, serverDefaults } from "../../config/index.js";

const defaults: Config = {
  keyDirectory: "/tmp",
  seedAdminEndpoints: [],
  seedAdminPasskeys: [],
  demoEndpoints: [],
  server: { ...serverDefaults, externalUrl: "http://localhost:3000" },
  security: {
    ...securityFieldDefaults,
    rpId: "localhost",
    allowedNetworks: ["127.0.0.1/32", "::1/128", "::ffff:127.0.0.1/128"],
    trustedWebauthnOrigins: ["http://localhost"],
  },
  notifications: { mcp: { debounceMs: 50 } },
  agentSocket: { proxyEnabled: false },
  hydra: {
    publicUrl: "http://localhost:4444",
    adminUrl: "http://localhost:4445",
    spa: {
      clientId: "shellwatch-web",
      redirectUri: "http://localhost:3000/auth/callback",
    },
    introspectionCacheTtlMs: 0,
    dcr: {
      allowedScopes: ["mcp", "agent"],
      redirectUriPatterns: ["^http://(127\\.0\\.0\\.1|localhost)(:\\d+)?(/.*)?$"],
    },
  },
};

export function makeTestConfig(
  overrides?: Partial<Omit<Config, "security">> & {
    security?: Partial<Config["security"]>;
  },
): Config {
  const base = structuredClone(defaults);
  if (!overrides) return base;

  const { security, ...rest } = overrides;
  return {
    ...base,
    ...rest,
    security: security ? { ...base.security, ...security } : base.security,
  };
}
