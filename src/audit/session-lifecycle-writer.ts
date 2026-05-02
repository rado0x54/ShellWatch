import type { TerminalManager } from "../terminal/index.js";
import type { CloseReason } from "../terminal/types.js";
import type { SessionLifecycleRepository } from "./session-lifecycle-repo.js";

export interface SessionLifecycleWriterDeps {
  terminalManager: TerminalManager;
  repo: SessionLifecycleRepository;
  /** Optional logger; defaults to no-op so this module is easy to drop in. */
  log?: { error(err: unknown, msg: string): void };
}

/**
 * Subscribes to TerminalManager status transitions and writes audit rows.
 *
 *   opening -> open       INSERT a row representing the live session
 *   * -> closed | error   UPDATE the row with closed_at, duration_ms, close_reason
 *
 * Lifecycle is single-shot: created at app start, kept alive for the process
 * lifetime. The dispose() method removes the listener for tests.
 */
export class SessionLifecycleWriter {
  private readonly statusListener: (e: {
    sessionId: string;
    status: string;
    previousStatus: string;
    reason?: CloseReason;
  }) => void;

  constructor(private deps: SessionLifecycleWriterDeps) {
    this.statusListener = (event) => this.handleStatusChange(event);
    this.deps.terminalManager.on("status-change", this.statusListener);
  }

  dispose(): void {
    this.deps.terminalManager.off("status-change", this.statusListener);
  }

  private handleStatusChange(event: {
    sessionId: string;
    status: string;
    previousStatus: string;
    reason?: CloseReason;
  }): void {
    const { sessionId, status, previousStatus, reason } = event;

    if (previousStatus === "opening" && status === "open") {
      this.recordOpen(sessionId);
      return;
    }

    if (status === "closed" || status === "error") {
      this.recordClose(sessionId, status, reason);
    }
  }

  private recordOpen(sessionId: string): void {
    const session = this.deps.terminalManager.getSession(sessionId);
    if (!session) return;
    try {
      this.deps.repo.insertOpen({
        sessionId: session.sessionId,
        accountId: session.accountId,
        endpointId: session.endpointId,
        source: session.source,
        status: "open",
        createdAt: session.createdAt.toISOString(),
        sourceIp: session.sourceIp,
        mcpReason: session.mcpReason,
        mcpClientName: session.mcpClientName,
        mcpClientVersion: session.mcpClientVersion,
        apiKeyLabel: session.apiKeyLabel,
        apiKeyPrefix: session.apiKeyPrefix,
      });
    } catch (err) {
      // Don't let an audit-write failure break the live session — it would
      // turn an observability concern into an availability incident.
      this.deps.log?.error(err, `Failed to record session open for ${sessionId}`);
    }
  }

  private recordClose(sessionId: string, status: string, reason: CloseReason | undefined): void {
    const session = this.deps.terminalManager.getSession(sessionId);
    if (!session) return;
    const closedAt = new Date();
    try {
      this.deps.repo.recordClose({
        sessionId: session.sessionId,
        status,
        closedAt: closedAt.toISOString(),
        durationMs: closedAt.getTime() - session.createdAt.getTime(),
        closeReason: reason ?? session.closeReason,
      });
    } catch (err) {
      this.deps.log?.error(err, `Failed to record session close for ${sessionId}`);
    }
  }
}
