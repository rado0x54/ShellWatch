// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { ConfigSchema } from "../config/index.js";
import { DEMO_ENDPOINT_ID_PREFIX, createDemoEndpointsService, isDemoEndpointId } from "./index.js";

function buildConfig(yaml: { demoEndpoints?: unknown }) {
  return ConfigSchema.parse({
    server: { externalUrl: "http://localhost:3000" },
    security: {
      rpId: "localhost",
      trustedWebauthnOrigins: ["http://localhost:3000"],
    },
    ...yaml,
  });
}

describe("isDemoEndpointId", () => {
  it("matches the demo prefix", () => {
    expect(isDemoEndpointId(`${DEMO_ENDPOINT_ID_PREFIX}abc123`)).toBe(true);
    expect(isDemoEndpointId("not-a-demo-id")).toBe(false);
    expect(isDemoEndpointId("")).toBe(false);
  });
});

describe("createDemoEndpointsService", () => {
  it("returns an empty list when config has no demo endpoints", () => {
    const cfg = buildConfig({});
    const svc = createDemoEndpointsService(cfg.demoEndpoints);
    expect(svc.list("acc1")).toEqual([]);
    expect(svc.isEmpty()).toBe(true);
  });

  it("synthesizes endpoints with stable demo: ids and accountId set", () => {
    const cfg = buildConfig({
      demoEndpoints: [
        { label: "Demo: Sudoku", address: "sw-sudoku@ssh.shellwatch.ai" },
        { label: "Demo: 2048", address: "sw-2048@ssh.shellwatch.ai" },
      ],
    });
    const svc = createDemoEndpointsService(cfg.demoEndpoints);
    const list = svc.list("acc-42");
    expect(list).toHaveLength(2);
    for (const e of list) {
      expect(e.id.startsWith(DEMO_ENDPOINT_ID_PREFIX)).toBe(true);
      expect(e.accountId).toBe("acc-42");
      expect(e.userVerification).toBe("required");
      expect(e.description).toBeNull();
    }
    // Different addresses produce distinct ids.
    expect(list[0].id).not.toBe(list[1].id);
  });

  it("preserves the agentForward flag from config", () => {
    const cfg = buildConfig({
      demoEndpoints: [
        { label: "demo-on", address: "alice@host-a" },
        { label: "demo-off", address: "bob@host-b", agentForward: false },
      ],
    });
    const svc = createDemoEndpointsService(cfg.demoEndpoints);
    const list = svc.list("acc1");
    expect(list[0].agentForward).toBe(true);
    expect(list[1].agentForward).toBe(false);
  });

  it("findById resolves a known demo id, scoped to the requesting account", () => {
    const cfg = buildConfig({
      demoEndpoints: [{ label: "Demo: Snake", address: "sw-snake@ssh.shellwatch.ai" }],
    });
    const svc = createDemoEndpointsService(cfg.demoEndpoints);
    const [synthesized] = svc.list("acc1");
    const found = svc.findById(synthesized.id, "acc-99");
    expect(found).not.toBeNull();
    expect(found!.accountId).toBe("acc-99");
    expect(found!.host).toBe("ssh.shellwatch.ai");
    expect(found!.username).toBe("sw-snake");
  });

  it("findById returns null for unknown or non-demo ids", () => {
    const cfg = buildConfig({
      demoEndpoints: [{ label: "Demo: Snake", address: "sw-snake@ssh.shellwatch.ai" }],
    });
    const svc = createDemoEndpointsService(cfg.demoEndpoints);
    expect(svc.findById("some-uuid", "acc1")).toBeNull();
    expect(svc.findById(`${DEMO_ENDPOINT_ID_PREFIX}deadbeef`, "acc1")).toBeNull();
  });

  it("produces a stable id across reconstructions with the same config", () => {
    const cfg = buildConfig({
      demoEndpoints: [{ label: "Demo: Sudoku", address: "sw-sudoku@ssh.shellwatch.ai" }],
    });
    const a = createDemoEndpointsService(cfg.demoEndpoints).list("acc1")[0].id;
    const b = createDemoEndpointsService(cfg.demoEndpoints).list("acc1")[0].id;
    expect(a).toBe(b);
  });
});
