import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { InMemoryEndpointRepository } from "../db/repositories/endpoint-repo.js";
import { TerminalManager } from "../terminal/index.js";
import type { TerminalTransport, TransportFactory } from "../terminal/transport.js";
import { buildSessionList, routeMessage, type WsClientContext } from "./ws-message-router.js";
import type { ServerMessage } from "./ws-protocol.js";

function createMockTransport(): TerminalTransport {
  const emitter = new EventEmitter();
  return Object.assign(emitter, {
    write: vi.fn(),
    resize: vi.fn(),
    close: vi.fn(),
  }) as unknown as TerminalTransport;
}

const ACCT_A = "acct-a";
const ACCT_B = "acct-b";

describe("ws-message-router account scoping", () => {
  let manager: TerminalManager;
  let uiCreatedSessions: Set<string>;
  let sessionA: string;
  let sessionB: string;

  beforeEach(async () => {
    const endpointRepo = new InMemoryEndpointRepository([
      { id: "endpoint-a", accountId: ACCT_A, label: "A", host: "h", port: 22, username: "u" },
      { id: "endpoint-b", accountId: ACCT_B, label: "B", host: "h", port: 22, username: "u" },
    ]);
    const transportFactory: TransportFactory = vi.fn().mockResolvedValue(createMockTransport());
    manager = new TerminalManager(endpointRepo, transportFactory, {
      idleTimeoutMs: 60_000,
      cleanupIntervalMs: 60_000,
    });
    uiCreatedSessions = new Set<string>();
    const a = await manager.create("endpoint-a", { kind: "ui", sourceIp: "1.1.1.1" });
    const b = await manager.create("endpoint-b", { kind: "ui", sourceIp: "2.2.2.2" });
    sessionA = a.sessionId;
    sessionB = b.sessionId;
    uiCreatedSessions.add(sessionA);
    uiCreatedSessions.add(sessionB);
  });

  function makeCtx(accountId: string): { ctx: WsClientContext; sent: ServerMessage[] } {
    const sent: ServerMessage[] = [];
    const ctx: WsClientContext = {
      attachedSessions: new Set(),
      controlledSessions: new Set(),
      accountId,
      send: (msg) => {
        sent.push(msg);
      },
      sendError: (message) => {
        sent.push({ type: "error", message });
      },
    };
    return { ctx, sent };
  }

  describe("buildSessionList", () => {
    it("filters sessions to those owned by the account", () => {
      const msg = buildSessionList(manager, new Set(), uiCreatedSessions, { accountId: ACCT_A });
      if (msg.type !== "sessions:changed") throw new Error("wrong type");
      expect(msg.sessions.map((s) => s.sessionId)).toEqual([sessionA]);
    });

    it("returns empty list when no sessions are owned by this account", () => {
      const msg = buildSessionList(manager, new Set(), uiCreatedSessions, {
        accountId: "ghost",
      });
      if (msg.type !== "sessions:changed") throw new Error("wrong type");
      expect(msg.sessions).toEqual([]);
    });
  });

  describe("routeMessage cross-account isolation", () => {
    const deps = () => ({ terminalManager: manager, uiCreatedSessions });

    it("rejects terminal:attach on a session owned by another account", () => {
      const { ctx, sent } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:attach", sessionId: sessionB }, ctx, deps());
      expect(ctx.attachedSessions.has(sessionB)).toBe(false);
      expect(sent).toEqual([{ type: "error", message: `Session not found: ${sessionB}` }]);
    });

    it("allows terminal:attach on a session owned by this account", () => {
      const { ctx, sent } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:attach", sessionId: sessionA }, ctx, deps());
      expect(ctx.attachedSessions.has(sessionA)).toBe(true);
      expect(sent.some((m) => m.type === "terminal:status")).toBe(true);
    });

    it("rejects terminal:close on a foreign session", () => {
      const { ctx, sent } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:close", sessionId: sessionB }, ctx, deps());
      expect(sent).toEqual([{ type: "error", message: `Session not found: ${sessionB}` }]);
      expect(manager.getSession(sessionB)?.status).not.toBe("closed");
    });

    it("rejects terminal:take-control on a foreign session", () => {
      const { ctx, sent } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:take-control", sessionId: sessionB }, ctx, deps());
      expect(ctx.controlledSessions.has(sessionB)).toBe(false);
      expect(sent).toEqual([{ type: "error", message: `Session not found: ${sessionB}` }]);
    });

    it("rejects terminal:input when not attached, even if uiCreatedSessions has the id", () => {
      // sessionB is in uiCreatedSessions globally — but this client (acct-a) never attached.
      const { ctx, sent } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:input", sessionId: sessionB, data: "rm -rf /" }, ctx, deps());
      expect(sent).toEqual([{ type: "error", message: `Session not attached: ${sessionB}` }]);
    });
  });
});
