import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { type EndpointInfo, InMemoryEndpointRepository } from "../db/repositories/endpoint-repo.js";
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
  let sessionA: string;
  let sessionB: string;
  let endpointA: EndpointInfo;
  let endpointB: EndpointInfo;

  beforeEach(async () => {
    const endpointRepo = new InMemoryEndpointRepository([
      { id: "endpoint-a", accountId: ACCT_A, label: "A", host: "h", port: 22, username: "u" },
      { id: "endpoint-b", accountId: ACCT_B, label: "B", host: "h", port: 22, username: "u" },
    ]);
    endpointA = (await endpointRepo.findByIdForAccount("endpoint-a", ACCT_A))!;
    endpointB = (await endpointRepo.findByIdForAccount("endpoint-b", ACCT_B))!;
    const transportFactory: TransportFactory = vi.fn().mockResolvedValue(createMockTransport());
    manager = new TerminalManager(transportFactory, {
      idleTimeoutMs: 60_000,
      cleanupIntervalMs: 60_000,
    });
    const a = await manager.create(endpointA, ACCT_A, { kind: "ui", sourceIp: "1.1.1.1" });
    const b = await manager.create(endpointB, ACCT_B, { kind: "ui", sourceIp: "2.2.2.2" });
    sessionA = a.sessionId;
    sessionB = b.sessionId;
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
      const msg = buildSessionList(manager, new Set(), { accountId: ACCT_A });
      if (msg.type !== "sessions:changed") throw new Error("wrong type");
      expect(msg.sessions.map((s) => s.sessionId)).toEqual([sessionA]);
    });

    it("returns empty list when no sessions are owned by this account", () => {
      const msg = buildSessionList(manager, new Set(), { accountId: "ghost" });
      if (msg.type !== "sessions:changed") throw new Error("wrong type");
      expect(msg.sessions).toEqual([]);
    });

    it("reports observer mode for sessions absent from controlledSessions", () => {
      const msg = buildSessionList(manager, new Set(), { accountId: ACCT_A });
      if (msg.type !== "sessions:changed") throw new Error("wrong type");
      expect(msg.sessions[0].mode).toBe("observer");
    });

    it("reports control mode when session is in controlledSessions", () => {
      const msg = buildSessionList(manager, new Set([sessionA]), { accountId: ACCT_A });
      if (msg.type !== "sessions:changed") throw new Error("wrong type");
      expect(msg.sessions[0].mode).toBe("control");
    });
  });

  describe("routeMessage cross-account isolation", () => {
    const deps = () => ({ terminalManager: manager });

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

    it("rejects terminal:input when not attached, even on a UI-sourced session", () => {
      // sessionB is UI-sourced — but this client (acct-a) never attached.
      const { ctx, sent } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:input", sessionId: sessionB, data: "rm -rf /" }, ctx, deps());
      expect(sent).toEqual([{ type: "error", message: `Session not attached: ${sessionB}` }]);
    });
  });

  describe("control state on attach", () => {
    const deps = () => ({ terminalManager: manager });

    it("attach to a UI-sourced session puts the client in control mode", () => {
      const { ctx, sent } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:attach", sessionId: sessionA }, ctx, deps());
      expect(ctx.controlledSessions.has(sessionA)).toBe(true);
      const modeMsg = sent.find((m) => m.type === "terminal:mode");
      expect(modeMsg).toEqual({ type: "terminal:mode", sessionId: sessionA, mode: "control" });
    });

    it("attach to an MCP-sourced session puts the client in observer mode", async () => {
      const c = await manager.create(endpointA, ACCT_A, {
        kind: "mcp",
        reason: "test",
        sourceIp: "3.3.3.3",
      });
      const { ctx, sent } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:attach", sessionId: c.sessionId }, ctx, deps());
      expect(ctx.controlledSessions.has(c.sessionId)).toBe(false);
      const modeMsg = sent.find((m) => m.type === "terminal:mode");
      expect(modeMsg).toEqual({
        type: "terminal:mode",
        sessionId: c.sessionId,
        mode: "observer",
      });
    });

    it("release-control on a UI-sourced session truly releases (regression for #123)", () => {
      const { ctx, sent } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:attach", sessionId: sessionA }, ctx, deps());
      expect(ctx.controlledSessions.has(sessionA)).toBe(true);

      routeMessage({ type: "terminal:release-control", sessionId: sessionA }, ctx, deps());
      expect(ctx.controlledSessions.has(sessionA)).toBe(false);

      // Subsequent input must be gated as observer (was a no-op pre-fix).
      sent.length = 0;
      routeMessage({ type: "terminal:input", sessionId: sessionA, data: "x" }, ctx, deps());
      expect(sent).toEqual([
        { type: "error", message: "Observer mode: take control first to send input" },
      ]);
    });

    it("release-control is a silent no-op for sessions this client never attached", () => {
      const { ctx, sent } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:release-control", sessionId: sessionA }, ctx, deps());
      expect(sent).toEqual([]);
      expect(ctx.controlledSessions.has(sessionA)).toBe(false);
    });

    it("a second client attaching to a UI session also enters control mode", () => {
      // UI-sourced sessions default to control for any client owned by the
      // account — the take-control handshake is opt-in only for non-UI sources.
      const { ctx: first } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:attach", sessionId: sessionA }, first, deps());
      expect(first.controlledSessions.has(sessionA)).toBe(true);

      const { ctx: second } = makeCtx(ACCT_A);
      routeMessage({ type: "terminal:attach", sessionId: sessionA }, second, deps());
      expect(second.controlledSessions.has(sessionA)).toBe(true);
    });
  });
});
