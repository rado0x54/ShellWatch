import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";
import type { Config } from "../config/index.js";
import { TerminalManager } from "./terminal-manager.js";
import type { TerminalTransport, TransportFactory } from "./transport.js";

function createMockTransport(): TerminalTransport {
  const emitter = new EventEmitter();
  return Object.assign(emitter, {
    write: vi.fn(),
    resize: vi.fn(),
    close: vi.fn(),
  }) as unknown as TerminalTransport;
}

const testConfig: Config = {
  servers: [
    {
      id: "test-server",
      label: "Test Server",
      host: "localhost",
      port: 22,
      username: "testuser",
      privateKeyPath: "/tmp/fake.pem",
    },
  ],
  security: { allowedNetworks: ["127.0.0.1/32"] },
  notifications: { mcp: { debounceMs: 100 } },
};

describe("TerminalManager", () => {
  let mockTransport: TerminalTransport;
  let transportFactory: TransportFactory;
  let manager: TerminalManager;

  beforeEach(() => {
    mockTransport = createMockTransport();
    transportFactory = vi.fn().mockResolvedValue(mockTransport);
    manager = new TerminalManager(testConfig, transportFactory, {
      idleTimeoutMs: 60_000,
      cleanupIntervalMs: 60_000,
    });
  });

  describe("create", () => {
    it("creates a session for a valid endpoint", async () => {
      const session = await manager.create("test-server", "ui");
      expect(session.sessionId).toMatch(/^sess_/);
      expect(session.endpointId).toBe("test-server");
      expect(session.status).toBe("open");
      expect(session.source).toBe("ui");
      expect(transportFactory).toHaveBeenCalledWith("test-server");
    });

    it("rejects unknown endpoints", async () => {
      await expect(manager.create("nonexistent", "ui")).rejects.toThrow("Unknown endpoint");
    });

    it("handles transport connection failure", async () => {
      (transportFactory as Mock).mockRejectedValue(new Error("Connection refused"));
      await expect(manager.create("test-server", "ui")).rejects.toThrow("Failed to connect");
    });

    it("emits status-change events", async () => {
      const events: string[] = [];
      manager.on("status-change", ({ status }) => events.push(status));
      await manager.create("test-server", "ui");
      expect(events).toContain("open");
    });
  });

  describe("sendInput", () => {
    it("sends input to the transport", async () => {
      const session = await manager.create("test-server", "ui");
      manager.sendInput(session.sessionId, "ls -la\n");
      expect(mockTransport.write).toHaveBeenCalledWith("ls -la\n");
    });

    it("rejects input to unknown session", () => {
      expect(() => manager.sendInput("nonexistent", "data")).toThrow("not found");
    });
  });

  describe("readOutput", () => {
    it("reads buffered output", async () => {
      const session = await manager.create("test-server", "ui");
      mockTransport.emit("data", "hello ");
      mockTransport.emit("data", "world");
      const result = manager.readOutput(session.sessionId);
      expect(result.data).toBe("hello world");
    });

    it("supports incremental reads", async () => {
      const session = await manager.create("test-server", "ui");
      mockTransport.emit("data", "aabbcc");
      const r1 = manager.readOutput(session.sessionId, 0, 2);
      expect(r1.data).toBe("aa");
      const r2 = manager.readOutput(session.sessionId, r1.offset);
      expect(r2.data).toBe("bbcc");
    });
  });

  describe("resize", () => {
    it("resizes the transport", async () => {
      const session = await manager.create("test-server", "ui");
      manager.resize(session.sessionId, 120, 40);
      expect(mockTransport.resize).toHaveBeenCalledWith(120, 40);
    });
  });

  describe("listSessions", () => {
    it("lists active sessions", async () => {
      await manager.create("test-server", "ui");
      await manager.create("test-server", "mcp");
      const sessions = manager.listSessions();
      expect(sessions).toHaveLength(2);
      expect(sessions[0].source).toBe("ui");
      expect(sessions[1].source).toBe("mcp");
    });

    it("excludes closed sessions", async () => {
      const session = await manager.create("test-server", "ui");
      manager.close(session.sessionId);
      expect(manager.listSessions()).toHaveLength(0);
    });
  });

  describe("getSession", () => {
    it("returns session by id", async () => {
      const session = await manager.create("test-server", "ui");
      const found = manager.getSession(session.sessionId);
      expect(found).not.toBeNull();
      expect(found?.sessionId).toBe(session.sessionId);
    });

    it("returns null for unknown session", () => {
      expect(manager.getSession("nonexistent")).toBeNull();
    });
  });

  describe("close", () => {
    it("closes the transport and cleans up", async () => {
      const session = await manager.create("test-server", "ui");
      manager.close(session.sessionId);
      expect(mockTransport.close).toHaveBeenCalled();
      expect(manager.getSession(session.sessionId)).toBeNull();
    });

    it("emits close event", async () => {
      const closed: string[] = [];
      manager.on("close", ({ sessionId }) => closed.push(sessionId));
      const session = await manager.create("test-server", "ui");
      manager.close(session.sessionId);
      expect(closed).toContain(session.sessionId);
    });

    it("is idempotent", async () => {
      const session = await manager.create("test-server", "ui");
      manager.close(session.sessionId);
      // Second close should not throw
      expect(() => manager.close(session.sessionId)).toThrow("not found");
    });
  });

  describe("transport events", () => {
    it("emits output events on transport data", async () => {
      const outputs: string[] = [];
      manager.on("output", ({ data }) => outputs.push(data));
      await manager.create("test-server", "ui");
      mockTransport.emit("data", "output line");
      expect(outputs).toContain("output line");
    });

    it("sets status to closed on transport close", async () => {
      const session = await manager.create("test-server", "ui");
      mockTransport.emit("close");
      const updated = manager.getSession(session.sessionId);
      expect(updated?.status).toBe("closed");
    });

    it("sets status to error on transport error", async () => {
      const session = await manager.create("test-server", "ui");
      mockTransport.emit("error", new Error("broken"));
      const updated = manager.getSession(session.sessionId);
      expect(updated?.status).toBe("error");
    });
  });

  describe("idle cleanup", () => {
    it("closes idle sessions", async () => {
      const mgr = new TerminalManager(testConfig, transportFactory, {
        idleTimeoutMs: 50,
        cleanupIntervalMs: 25,
      });
      const session = await mgr.create("test-server", "ui");

      await new Promise((r) => setTimeout(r, 100));

      expect(mgr.getSession(session.sessionId)).toBeNull();
      mgr.destroy();
    });
  });

  describe("destroy", () => {
    it("closes all sessions", async () => {
      await manager.create("test-server", "ui");
      await manager.create("test-server", "mcp");
      manager.destroy();
      expect(manager.listSessions()).toHaveLength(0);
    });
  });
});
