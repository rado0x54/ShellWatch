import type { EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { EndpointAuthTrigger } from "../pending-action/types.js";
import type { OutputReadResult, TerminalManager, TerminalSession } from "../terminal/index.js";
import { resolveKeys } from "../terminal/keys.js";
import { sanitizeClientReportedValue } from "../util/sanitize-client-info.js";

export type AgentSource = "mcp" | "ssh";

export interface AgentSessionOptions {
  endpointRepo: EndpointRepository;
  terminalManager: TerminalManager;
  source: AgentSource;
  /**
   * Owning account id. Scopes endpoint listings/lookups so this session can
   * only see endpoints belonging to the calling account.
   */
  accountId: string;
  maxSessions?: number;
  /** Source IP of the calling agent (used when building the signing trigger). */
  sourceIp?: string;
}

/**
 * An AgentSession manages the terminal sessions owned by a single agent connection.
 * Both MCP clients and SSH server clients use this to ensure session isolation —
 * each agent can only see and interact with its own sessions.
 *
 * When the agent disconnects, all owned sessions are closed.
 */
export class AgentSession {
  private ownedSessions = new Set<string>();

  private mcpClientName?: string;
  private mcpClientVersion?: string;

  private readonly endpointRepo: EndpointRepository;
  private readonly terminalManager: TerminalManager;
  private readonly source: AgentSource;
  private readonly accountId: string;
  private readonly maxSessions: number;
  private readonly sourceIp?: string;

  constructor(opts: AgentSessionOptions) {
    this.endpointRepo = opts.endpointRepo;
    this.terminalManager = opts.terminalManager;
    this.source = opts.source;
    this.accountId = opts.accountId;
    this.maxSessions = opts.maxSessions ?? 5;
    this.sourceIp = opts.sourceIp;
  }

  /**
   * Record the calling MCP client's advertised clientInfo (from the initialize
   * handshake). Re-sanitizes defensively so any future caller can't bypass the
   * trust-boundary cleaning by accident — sanitizeClientReportedValue is
   * idempotent so callers that already sanitized pay nothing meaningful.
   */
  setMcpClientInfo(info: { name?: string; version?: string }): void {
    this.mcpClientName = sanitizeClientReportedValue(info.name);
    this.mcpClientVersion = sanitizeClientReportedValue(info.version);
  }

  /** Sessions owned by this agent */
  get sessions(): ReadonlySet<string> {
    return this.ownedSessions;
  }

  async listEndpoints(): Promise<
    {
      id: string;
      label: string;
      host: string;
      port: number;
      username: string;
      description: string | null;
    }[]
  > {
    const endpoints = await this.endpointRepo.findAllForAccount(this.accountId);
    return endpoints.map(({ id, label, host, port, username, description }) => ({
      id,
      label,
      host,
      port,
      username,
      description,
    }));
  }

  async createSession(endpointId: string, reason: string): Promise<TerminalSession> {
    if (this.ownedSessions.size >= this.maxSessions) {
      throw new Error(`Maximum concurrent sessions (${this.maxSessions}) reached`);
    }
    // AgentSource is "mcp" | "ssh"; today only MCP is implemented. The SSH
    // server interface (issue #12) isn't wired in yet — when it lands, extend
    // EndpointAuthTrigger with an "ssh" kind and branch here.
    const trigger: EndpointAuthTrigger = {
      kind: "mcp",
      reason,
      sourceIp: this.sourceIp,
      mcpClientName: this.mcpClientName,
      mcpClientVersion: this.mcpClientVersion,
    };
    const session = await this.terminalManager.create(endpointId, trigger);
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
