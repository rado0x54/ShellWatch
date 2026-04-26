import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { InMemoryEndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { TerminalManager } from "../terminal/terminal-manager.js";
import { AgentSession } from "./agent-session.js";

function createMockTerminalManager() {
  const emitter = new EventEmitter();
  return Object.assign(emitter, {
    create: vi.fn(),
    sendInput: vi.fn(),
    sendKeys: vi.fn(),
    readOutput: vi.fn(),
    resize: vi.fn(),
    listSessions: vi.fn().mockReturnValue([]),
    getSession: vi.fn(),
    close: vi.fn(),
    destroy: vi.fn(),
  }) as unknown as TerminalManager;
}

describe("AgentSession.listEndpoints", () => {
  it("returns only endpoints owned by the calling account", async () => {
    // Same repo holds endpoints for two accounts. Pre-fix this method called
    // findAll() and surfaced both — feeding cross-account hostnames/usernames
    // into the MCP `instructions` string at session initialize.
    const endpointRepo = new InMemoryEndpointRepository([
      {
        id: "alice-box",
        accountId: "account-alice",
        label: "Alice prod",
        host: "alice.internal",
        port: 22,
        username: "alice",
      },
      {
        id: "bob-box",
        accountId: "account-bob",
        label: "Bob prod",
        host: "bob.internal",
        port: 22,
        username: "bob",
      },
    ]);
    const session = new AgentSession({
      endpointRepo,
      terminalManager: createMockTerminalManager(),
      source: "mcp",
      accountId: "account-alice",
    });

    const visible = await session.listEndpoints();

    expect(visible.map((e) => e.id)).toEqual(["alice-box"]);
    expect(visible.some((e) => e.host === "bob.internal")).toBe(false);
  });
});

describe("AgentSession.createSession", () => {
  it("rejects endpoints owned by a different account", async () => {
    // Pre-fix: createSession passed endpointId straight to terminalManager.create
    // with no ownership check, so caller B could trigger a WebAuthn prompt on
    // owner A's endpoint and (if approved) drive the resulting session.
    const endpointRepo = new InMemoryEndpointRepository([
      {
        id: "alice-box",
        accountId: "account-alice",
        label: "Alice prod",
        host: "alice.internal",
        port: 22,
        username: "alice",
      },
    ]);
    const terminalManager = createMockTerminalManager();
    const session = new AgentSession({
      endpointRepo,
      terminalManager,
      source: "mcp",
      accountId: "account-bob",
    });

    await expect(session.createSession("alice-box", "phishy reason")).rejects.toThrow(
      /Unknown endpoint/,
    );
    expect(terminalManager.create).not.toHaveBeenCalled();
  });

  it("creates a session when caller owns the endpoint", async () => {
    const endpointRepo = new InMemoryEndpointRepository([
      {
        id: "alice-box",
        accountId: "account-alice",
        label: "Alice prod",
        host: "alice.internal",
        port: 22,
        username: "alice",
      },
    ]);
    const terminalManager = createMockTerminalManager();
    vi.mocked(terminalManager.create).mockResolvedValue({
      sessionId: "sess_1",
      endpointId: "alice-box",
      accountId: "account-alice",
      status: "open",
      createdAt: new Date(),
      lastActivityAt: new Date(),
      source: "mcp",
    });
    const session = new AgentSession({
      endpointRepo,
      terminalManager,
      source: "mcp",
      accountId: "account-alice",
    });

    const created = await session.createSession("alice-box", "legit work");

    expect(created.sessionId).toBe("sess_1");
    expect(terminalManager.create).toHaveBeenCalledWith(
      expect.objectContaining({ id: "alice-box", accountId: "account-alice" }),
      expect.objectContaining({ kind: "mcp", reason: "legit work" }),
    );
  });
});
