import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { TerminalManager } from "../terminal/index.js";
import type { TerminalSession } from "../terminal/types.js";
import type { SessionLifecycleRepository } from "./session-lifecycle-repo.js";
import { SessionLifecycleWriter } from "./session-lifecycle-writer.js";

interface FakeManager extends EventEmitter {
  getSession(id: string): TerminalSession | null;
}

function makeFakeManager(session: TerminalSession): FakeManager {
  const emitter = new EventEmitter();
  return Object.assign(emitter, {
    getSession: (id: string) => (id === session.sessionId ? session : null),
  });
}

function makeRepo(): SessionLifecycleRepository {
  return {
    insertOpen: vi.fn(),
    recordClose: vi.fn(),
    list: vi.fn(),
  };
}

const baseSession: TerminalSession = {
  sessionId: "sess_1",
  accountId: "acct_a",
  endpointId: "ep_1",
  status: "opening",
  createdAt: new Date("2026-01-01T00:00:00Z"),
  lastActivityAt: new Date("2026-01-01T00:00:00Z"),
  source: "ui",
  sourceIp: "127.0.0.1",
};

describe("SessionLifecycleWriter", () => {
  let manager: FakeManager;
  let repo: SessionLifecycleRepository;
  let writer: SessionLifecycleWriter;

  beforeEach(() => {
    manager = makeFakeManager({ ...baseSession });
    repo = makeRepo();
    writer = new SessionLifecycleWriter({
      terminalManager: manager as unknown as TerminalManager,
      repo,
    });
  });

  it("inserts an open row on opening -> open", () => {
    manager.emit("status-change", {
      sessionId: "sess_1",
      status: "open",
      previousStatus: "opening",
    });
    expect(repo.insertOpen).toHaveBeenCalledTimes(1);
    expect(repo.recordClose).not.toHaveBeenCalled();
  });

  it("does not insert when the open transition skips the opening precondition", () => {
    // E.g. error path during create() that never reaches `open` from `opening`.
    manager.emit("status-change", {
      sessionId: "sess_1",
      status: "open",
      previousStatus: "open",
    });
    expect(repo.insertOpen).not.toHaveBeenCalled();
  });

  it("records a close on open -> closed", () => {
    manager.emit("status-change", {
      sessionId: "sess_1",
      status: "closed",
      previousStatus: "closing",
      reason: "client.ui",
    });
    expect(repo.recordClose).toHaveBeenCalledTimes(1);
    const arg = vi.mocked(repo.recordClose).mock.calls[0]![0];
    expect(arg.status).toBe("closed");
    expect(arg.closeReason).toBe("client.ui");
  });

  it("records a close on open -> error", () => {
    manager.emit("status-change", {
      sessionId: "sess_1",
      status: "error",
      previousStatus: "open",
      reason: "transport-error",
    });
    expect(repo.recordClose).toHaveBeenCalledTimes(1);
    expect(vi.mocked(repo.recordClose).mock.calls[0]![0].status).toBe("error");
  });

  it("ignores intermediate -> closing transitions", () => {
    manager.emit("status-change", {
      sessionId: "sess_1",
      status: "closing",
      previousStatus: "open",
      reason: "shutdown",
    });
    expect(repo.recordClose).not.toHaveBeenCalled();
  });

  it("dispose removes the listener so no further writes happen", () => {
    writer.dispose();
    manager.emit("status-change", {
      sessionId: "sess_1",
      status: "closed",
      previousStatus: "closing",
      reason: "client.ui",
    });
    expect(repo.recordClose).not.toHaveBeenCalled();
  });

  it("swallows repo errors so audit failures don't crash the live session", () => {
    vi.mocked(repo.insertOpen).mockImplementation(() => {
      throw new Error("disk full");
    });
    expect(() =>
      manager.emit("status-change", {
        sessionId: "sess_1",
        status: "open",
        previousStatus: "opening",
      }),
    ).not.toThrow();
  });
});
