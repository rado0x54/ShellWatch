import { type Config, securityFieldDefaults, serverDefaults } from "../../config/index.js";
import { defaultOAuthConfig } from "../../oauth/config.js";

const defaults: Config = {
  keyDirectory: "/tmp",
  seedAdminEndpoints: [],
  seedAdminPasskeys: [],
  server: { ...serverDefaults, externalUrl: "http://localhost:3000" },
  security: {
    ...securityFieldDefaults,
    rpId: "localhost",
    allowedNetworks: ["127.0.0.1/32", "::1/128", "::ffff:127.0.0.1/128"],
    trustedWebauthnOrigins: ["http://localhost"],
  },
  notifications: { mcp: { debounceMs: 50 } },
  agentSocket: { proxyEnabled: false },
  oauth: defaultOAuthConfig,
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
