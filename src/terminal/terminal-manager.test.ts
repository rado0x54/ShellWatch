// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";
import type { EndpointInfo } from "../db/repositories/endpoint-repo.js";
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

const testEndpoint: EndpointInfo = {
  id: "test-server",
  accountId: "test-account",
  label: "Test Server",
  host: "localhost",
  port: 22,
  username: "testuser",
  userVerification: "required",
  description: null,
};

describe("TerminalManager", () => {
  let mockTransport: TerminalTransport;
  let transportFactory: TransportFactory;
  let manager: TerminalManager;

  beforeEach(() => {
    mockTransport = createMockTransport();
    transportFactory = vi.fn().mockResolvedValue(mockTransport);
    manager = new TerminalManager(transportFactory, {
      idleTimeoutMs: 60_000,
      cleanupIntervalMs: 60_000,
    });
  });

  describe("create", () => {
    it("creates a session for a valid endpoint", async () => {
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      expect(session.sessionId).toMatch(/^sess_/);
      expect(session.endpointId).toBe("test-server");
      expect(session.accountId).toBe("test-account");
      expect(session.status).toBe("open");
      expect(session.source).toBe("ui");
      expect(transportFactory).toHaveBeenCalledWith(
        expect.objectContaining({ endpoint: testEndpoint }),
      );
    });

    it("handles transport connection failure", async () => {
      (transportFactory as Mock).mockRejectedValue(new Error("Connection refused"));
      await expect(
        manager.create(testEndpoint, "test-account", { kind: "ui", sourceIp: "127.0.0.1" }),
      ).rejects.toThrow("Failed to connect");
    });

    it("rejects an endpoint whose accountId does not match the caller (defensive backstop, #130)", async () => {
      await expect(
        manager.create(testEndpoint, "different-account", {
          kind: "ui",
          sourceIp: "127.0.0.1",
        }),
      ).rejects.toThrow(/Unknown endpoint/);
      expect(transportFactory).not.toHaveBeenCalled();
    });

    it("emits status-change events", async () => {
      const events: string[] = [];
      manager.on("status-change", ({ status }) => events.push(status));
      await manager.create(testEndpoint, "test-account", { kind: "ui", sourceIp: "127.0.0.1" });
      expect(events).toContain("open");
    });
  });

  describe("sendInput", () => {
    it("sends input to the transport", async () => {
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      manager.sendInput(session.sessionId, "ls -la\n");
      expect(mockTransport.write).toHaveBeenCalledWith("ls -la\n");
    });

    it("rejects input to unknown session", () => {
      expect(() => manager.sendInput("nonexistent", "data")).toThrow("not found");
    });
  });

  describe("readOutput", () => {
    it("reads buffered output", async () => {
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      mockTransport.emit("data", "hello ");
      mockTransport.emit("data", "world");
      const result = manager.readOutput(session.sessionId);
      expect(result.data).toBe("hello world");
    });

    it("supports incremental reads", async () => {
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      mockTransport.emit("data", "aabbcc");
      const r1 = manager.readOutput(session.sessionId, 0, 2);
      expect(r1.data).toBe("aa");
      const r2 = manager.readOutput(session.sessionId, r1.offset);
      expect(r2.data).toBe("bbcc");
    });
  });

  describe("resize", () => {
    it("resizes the transport", async () => {
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      manager.resize(session.sessionId, 120, 40);
      expect(mockTransport.resize).toHaveBeenCalledWith(120, 40);
    });
  });

  describe("listSessions", () => {
    it("lists active sessions", async () => {
      await manager.create(testEndpoint, "test-account", { kind: "ui", sourceIp: "127.0.0.1" });
      await manager.create(testEndpoint, "test-account", {
        kind: "mcp",
        sourceIp: "127.0.0.1",
        reason: "test",
      });
      const sessions = manager.listSessions();
      expect(sessions).toHaveLength(2);
      expect(sessions[0].source).toBe("ui");
      expect(sessions[1].source).toBe("mcp");
    });

    it("excludes closed sessions", async () => {
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      manager.close(session.sessionId, "client.ui");
      expect(manager.listSessions()).toHaveLength(0);
    });
  });

  describe("getSession", () => {
    it("returns session by id", async () => {
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
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
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      manager.close(session.sessionId, "client.ui");
      expect(mockTransport.close).toHaveBeenCalled();
      expect(manager.getSession(session.sessionId)).toBeNull();
    });

    it("emits close event", async () => {
      const closed: string[] = [];
      manager.on("close", ({ sessionId }) => closed.push(sessionId));
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      manager.close(session.sessionId, "client.ui");
      expect(closed).toContain(session.sessionId);
    });

    it("throws when called on an already-closed session", async () => {
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      manager.close(session.sessionId, "client.ui");
      expect(() => manager.close(session.sessionId, "client.ui")).toThrow("not found");
    });

    it("preserves the originating close reason even if transport emits 'close' synchronously", async () => {
      // Build a transport whose close() synchronously fires the 'close' event
      // — this is the contract corner ssh2 happens not to hit today, but the
      // code must not depend on that. The status-change for "closed" must
      // carry the originating reason from manager.close(), not the
      // server-hangup fallback used when no in-flight reason exists.
      const syncTransport = createMockTransport();
      (syncTransport as unknown as { close: () => void }).close = vi.fn(() => {
        syncTransport.emit("close");
      });
      const factory = vi.fn().mockResolvedValue(syncTransport);
      const m = new TerminalManager(factory, {
        idleTimeoutMs: 60_000,
        cleanupIntervalMs: 60_000,
      });
      const session = await m.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      const events: { status: string; reason?: string }[] = [];
      m.on("status-change", (e) => events.push({ status: e.status, reason: e.reason }));

      m.close(session.sessionId, "client.ui");

      const closedEvent = events.find((e) => e.status === "closed");
      expect(closedEvent?.reason).toBe("client.ui");
      m.destroy();
    });
  });

  describe("closeAllForAccount", () => {
    it("closes only sessions owned by the target account and returns the count", async () => {
      const acctA = "acct-a";
      const acctB = "acct-b";
      const epA: EndpointInfo = { ...testEndpoint, id: "ep-a", accountId: acctA };
      const epB: EndpointInfo = { ...testEndpoint, id: "ep-b", accountId: acctB };

      const a1 = await manager.create(epA, acctA, { kind: "ui", sourceIp: "1.1.1.1" });
      const a2 = await manager.create(epA, acctA, { kind: "ui", sourceIp: "1.1.1.1" });
      const b1 = await manager.create(epB, acctB, { kind: "ui", sourceIp: "2.2.2.2" });

      const closed = manager.closeAllForAccount(acctA, "account-deleted");
      expect(closed).toBe(2);

      // A's sessions are gone
      expect(manager.getSession(a1.sessionId)).toBeNull();
      expect(manager.getSession(a2.sessionId)).toBeNull();
      // B's session survives
      expect(manager.getSession(b1.sessionId)?.status).toBe("open");
    });

    it("returns 0 when the account has no live sessions", async () => {
      expect(manager.closeAllForAccount("ghost", "account-deleted")).toBe(0);
    });
  });

  describe("transport events", () => {
    it("emits output events on transport data", async () => {
      const outputs: string[] = [];
      manager.on("output", ({ data }) => outputs.push(data));
      await manager.create(testEndpoint, "test-account", { kind: "ui", sourceIp: "127.0.0.1" });
      mockTransport.emit("data", "output line");
      expect(outputs).toContain("output line");
    });

    it("sets status to closed on transport close", async () => {
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      mockTransport.emit("close");
      const updated = manager.getSession(session.sessionId);
      expect(updated?.status).toBe("closed");
    });

    it("sets status to error on transport error", async () => {
      const session = await manager.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      mockTransport.emit("error", new Error("broken"));
      const updated = manager.getSession(session.sessionId);
      expect(updated?.status).toBe("error");
    });
  });

  describe("idle cleanup", () => {
    it("closes idle sessions", async () => {
      const mgr = new TerminalManager(transportFactory, {
        idleTimeoutMs: 50,
        cleanupIntervalMs: 25,
      });
      const session = await mgr.create(testEndpoint, "test-account", {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });

      await new Promise((r) => setTimeout(r, 100));

      expect(mgr.getSession(session.sessionId)).toBeNull();
      mgr.destroy();
    });
  });

  describe("destroy", () => {
    it("closes all sessions", async () => {
      await manager.create(testEndpoint, "test-account", { kind: "ui", sourceIp: "127.0.0.1" });
      await manager.create(testEndpoint, "test-account", {
        kind: "mcp",
        sourceIp: "127.0.0.1",
        reason: "test",
      });
      manager.destroy();
      expect(manager.listSessions()).toHaveLength(0);
    });
  });
});
