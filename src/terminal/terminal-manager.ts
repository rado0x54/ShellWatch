import { EventEmitter } from "node:events";
import type { EndpointInfo } from "../db/repositories/endpoint-repo.js";
import type { EndpointAuthTrigger } from "../pending-action/types.js";
import { resolveKeys } from "./keys.js";
import { OutputBuffer } from "./output-buffer.js";
import type { TerminalTransport, TransportFactory } from "./transport.js";
import {
  type CloseReason,
  generateSessionId,
  type OutputReadResult,
  type TerminalEventMap,
  type TerminalSession,
  type TerminalStatus,
} from "./types.js";

interface ManagedTerminal {
  session: TerminalSession;
  transport: TerminalTransport;
  output: OutputBuffer;
}

export interface TerminalManagerOptions {
  idleTimeoutMs?: number;
  cleanupIntervalMs?: number;
  maxOutputBufferSize?: number;
}

const DEFAULT_IDLE_TIMEOUT = 30 * 60 * 1000; // 30 minutes
const DEFAULT_CLEANUP_INTERVAL = 60 * 1000; // 1 minute

export class TerminalManager extends EventEmitter<TerminalEventMap> {
  private terminals = new Map<string, ManagedTerminal>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private idleTimeoutMs: number;
  private maxOutputBufferSize: number | undefined;

  constructor(
    private transportFactory: TransportFactory,
    options: TerminalManagerOptions = {},
  ) {
    super();
    this.idleTimeoutMs = options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT;
    this.maxOutputBufferSize = options.maxOutputBufferSize;

    const cleanupInterval = options.cleanupIntervalMs ?? DEFAULT_CLEANUP_INTERVAL;
    this.cleanupTimer = setInterval(() => this.cleanupIdleTerminals(), cleanupInterval);
    this.cleanupTimer.unref();
  }

  // Callers (HTTP routes, AgentSession) must pass the caller's accountId and
  // an EndpointInfo they've already scoped via findByIdForAccount. The
  // assertion below is a defensive backstop: it makes the caller-supplied
  // ownership invariant load-bearing at runtime, so a future call site that
  // forgets to scope will fail loudly here instead of silently triggering a
  // WebAuthn prompt on the wrong tenant. See #130.
  async create(
    endpoint: EndpointInfo,
    expectedAccountId: string,
    trigger: EndpointAuthTrigger,
  ): Promise<TerminalSession> {
    if (endpoint.accountId !== expectedAccountId) {
      throw new Error(`Unknown endpoint: ${endpoint.id}`);
    }
    const sessionId = generateSessionId();
    const now = new Date();

    const session: TerminalSession = {
      sessionId,
      endpointId: endpoint.id,
      accountId: endpoint.accountId,
      status: "opening",
      createdAt: now,
      lastActivityAt: now,
      // trigger.kind is intentionally the same string set as TerminalSource for
      // the kinds we implement today (ui, mcp). When the planned "ssh" agent
      // source lands (#12), extend EndpointAuthTrigger to include it.
      source: trigger.kind,
      sourceIp: trigger.sourceIp,
      ...(trigger.kind === "mcp" && {
        mcpReason: trigger.reason,
        mcpClientName: trigger.mcpClientName,
        mcpClientVersion: trigger.mcpClientVersion,
        apiKeyLabel: trigger.apiKeyLabel,
        apiKeyPrefix: trigger.apiKeyPrefix,
      }),
    };

    const output = new OutputBuffer(this.maxOutputBufferSize);

    let transport: TerminalTransport;
    try {
      transport = await this.transportFactory({ endpoint, sessionId, trigger });
    } catch (err) {
      session.status = "error";
      throw new Error(`Failed to connect to ${endpoint.id}: ${(err as Error).message}`, {
        cause: err,
      });
    }

    const managed: ManagedTerminal = { session, transport, output };
    this.terminals.set(sessionId, managed);

    transport.on("data", (data: string) => {
      output.append(data);
      managed.session.lastActivityAt = new Date();
      this.emit("output", { sessionId, data, offset: output.currentOffset });
    });

    transport.on("close", () => {
      // If we already started a client-initiated close, preserve the originating
      // reason (set by close()/setStatus); only fall back to server-hangup for
      // transport-driven closes that arrive without a reason already in flight.
      this.setStatus(managed, "closed", managed.session.closeReason ?? "server-hangup");
    });

    transport.on("error", () => {
      this.setStatus(managed, "error", managed.session.closeReason ?? "transport-error");
    });

    this.setStatus(managed, "open");
    return { ...session, status: "open" };
  }

  sendInput(sessionId: string, input: string): void {
    const managed = this.getManaged(sessionId);
    if (managed.session.status !== "open") {
      throw new Error(`Terminal ${sessionId} is not open (status: ${managed.session.status})`);
    }
    managed.transport.write(input);
    managed.session.lastActivityAt = new Date();
  }

  sendKeys(sessionId: string, keys: string[]): void {
    const managed = this.getManaged(sessionId);
    if (managed.session.status !== "open") {
      throw new Error(`Terminal ${sessionId} is not open (status: ${managed.session.status})`);
    }
    const data = resolveKeys(keys);
    managed.transport.write(data);
    managed.session.lastActivityAt = new Date();
  }

  readOutput(sessionId: string, afterOffset?: number, limit?: number): OutputReadResult {
    const managed = this.getManaged(sessionId);
    return managed.output.read(afterOffset, limit);
  }

  /** Full-tail read from `afterOffset`, with `reset` when caller is behind the ring. */
  readOutputFrom(
    sessionId: string,
    afterOffset?: number,
  ): { data: string; offset: number; reset: boolean } {
    const managed = this.getManaged(sessionId);
    return managed.output.readFrom(afterOffset);
  }

  /** Return up to `limit` characters from the tail of the session's output. */
  readOutputTail(sessionId: string, limit: number): string {
    const managed = this.getManaged(sessionId);
    return managed.output.tail(limit);
  }

  resize(sessionId: string, cols: number, rows: number): void {
    const managed = this.getManaged(sessionId);
    if (managed.session.status !== "open") {
      throw new Error(`Terminal ${sessionId} is not open (status: ${managed.session.status})`);
    }
    managed.transport.resize(cols, rows);
  }

  listSessions(): TerminalSession[] {
    return Array.from(this.terminals.values())
      .filter((m) => m.session.status !== "closed")
      .map((m) => ({ ...m.session }));
  }

  getSession(sessionId: string): TerminalSession | null {
    const managed = this.terminals.get(sessionId);
    return managed ? { ...managed.session } : null;
  }

  close(sessionId: string, reason?: CloseReason): void {
    const managed = this.getManaged(sessionId);
    if (managed.session.status === "closed" || managed.session.status === "closing") {
      return;
    }
    this.setStatus(managed, "closing", reason);
    managed.transport.close();
    managed.output.clear();
    this.setStatus(managed, "closed", reason);
    this.terminals.delete(sessionId);
  }

  /** Close every live session owned by `accountId`. Returns the number closed. */
  closeAllForAccount(accountId: string, reason: CloseReason): number {
    let count = 0;
    for (const sessionId of this.listSessions()
      .filter((s) => s.accountId === accountId)
      .map((s) => s.sessionId)) {
      this.close(sessionId, reason);
      count++;
    }
    return count;
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    for (const sessionId of this.terminals.keys()) {
      this.close(sessionId, "shutdown");
    }
  }

  private getManaged(sessionId: string): ManagedTerminal {
    const managed = this.terminals.get(sessionId);
    if (!managed) {
      throw new Error(`Terminal session not found: ${sessionId}`);
    }
    return managed;
  }

  private setStatus(managed: ManagedTerminal, status: TerminalStatus, reason?: CloseReason): void {
    const previousStatus = managed.session.status;
    if (previousStatus === status) return;
    managed.session.status = status;
    // `closing` is included so the originating reason from close() is captured
    // BEFORE transport.close() runs. If the transport ever emits 'close'
    // synchronously inside its close() call, the listener fires with the saved
    // reason rather than falling back to "server-hangup".
    if (
      (status === "closing" || status === "closed" || status === "error") &&
      reason &&
      !managed.session.closeReason
    ) {
      managed.session.closeReason = reason;
    }
    this.emit("status-change", {
      sessionId: managed.session.sessionId,
      status,
      previousStatus,
      reason: managed.session.closeReason,
    });
    if (status === "closed") {
      this.emit("close", {
        sessionId: managed.session.sessionId,
        reason: managed.session.closeReason,
      });
    }
  }

  private cleanupIdleTerminals(): void {
    const now = Date.now();
    for (const [sessionId, managed] of this.terminals) {
      if (managed.session.status !== "open") continue;
      const idle = now - managed.session.lastActivityAt.getTime();
      if (idle > this.idleTimeoutMs) {
        this.close(sessionId, "idle-timeout");
      }
    }
  }
}
