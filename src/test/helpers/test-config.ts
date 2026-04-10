import { type Config, securityFieldDefaults, serverDefaults } from "../../config/index.js";

const defaults: Config = {
  keyDirectory: "/tmp",
  seedAdminEndpoints: [],
  seedAdminPasskeys: [],
  server: { ...serverDefaults },
  security: {
    ...securityFieldDefaults,
    rpId: "localhost",
    allowedNetworks: ["127.0.0.1/32", "::1/128", "::ffff:127.0.0.1/128"],
    trustedWebauthnOrigins: ["http://localhost"],
  },
  notifications: { mcp: { debounceMs: 50 } },
  agentSocket: { proxyEnabled: false },
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
