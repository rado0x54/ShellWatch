import type { Config } from "../config/index.js";
import type { OutputReadResult, TerminalManager, TerminalSession } from "../terminal/index.js";
import { resolveKeys } from "../terminal/keys.js";

export type AgentSource = "mcp" | "ssh";

/**
 * An AgentSession manages the terminal sessions owned by a single agent connection.
 * Both MCP clients and SSH server clients use this to ensure session isolation —
 * each agent can only see and interact with its own sessions.
 *
 * When the agent disconnects, all owned sessions are closed.
 */
export class AgentSession {
  private ownedSessions = new Set<string>();

  constructor(
    private config: Config,
    private terminalManager: TerminalManager,
    private source: AgentSource,
  ) {}

  /** Sessions owned by this agent */
  get sessions(): ReadonlySet<string> {
    return this.ownedSessions;
  }

  listEndpoints() {
    return this.config.servers.map(({ id, label, host, port, username }) => ({
      id,
      label,
      host,
      port,
      username,
    }));
  }

  async createSession(endpointId: string): Promise<TerminalSession> {
    const session = await this.terminalManager.create(endpointId, this.source);
    this.ownedSessions.add(session.sessionId);
    return session;
  }

  listSessions(): TerminalSession[] {
    return this.terminalManager.listSessions().filter((s) => this.ownedSessions.has(s.sessionId));
  }

  sendKeys(sessionId: string, keys: string[]): void {
    this.assertOwnership(sessionId);
    const data = resolveKeys(keys);
    this.terminalManager.sendInput(sessionId, data);
  }

  readOutput(sessionId: string, afterOffset?: number, limit?: number): OutputReadResult {
    this.assertOwnership(sessionId);
    return this.terminalManager.readOutput(sessionId, afterOffset, limit);
  }

  closeSession(sessionId: string): void {
    this.assertOwnership(sessionId);
    this.terminalManager.close(sessionId);
    this.ownedSessions.delete(sessionId);
  }

  /** Close all owned sessions — called on agent disconnect */
  destroy(): void {
    for (const sessionId of this.ownedSessions) {
      try {
        this.terminalManager.close(sessionId);
      } catch {
        // Session may already be closed
      }
    }
    this.ownedSessions.clear();
  }

  private assertOwnership(sessionId: string): void {
    if (!this.ownedSessions.has(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
  }
}
