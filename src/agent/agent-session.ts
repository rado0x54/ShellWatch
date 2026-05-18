// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { DemoEndpointsService } from "../demo-endpoints/index.js";
import { isDemoEndpointId } from "../demo-endpoints/index.js";
import type { EndpointAuthTrigger } from "../pending-action/types.js";
import type { OutputReadResult, TerminalManager, TerminalSession } from "../terminal/index.js";
import { resolveKeys } from "../terminal/keys.js";
import { sanitizeClientReportedValue } from "../util/sanitize-client-info.js";

export type AgentSource = "mcp" | "ssh";

export interface AgentSessionOptions {
  endpointRepo: EndpointRepository;
  /**
   * Service that materializes the operator-configured demo endpoints. Merged
   * into the agent's endpoint listing when the account's showDemoEndpoints
   * toggle is on; opens are accepted on `demo:*` ids regardless of the toggle
   * (matches the UI flow — visibility hides them, but the connect path stays
   * usable for callers that already know the id).
   */
  demoEndpoints: DemoEndpointsService;
  /** Used to read the account's `showDemoEndpoints` toggle at list time. */
  accountRepo: AccountRepository;
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
  /** API key label / prefix used to authenticate the agent connection (audit log #184). */
  apiKeyLabel?: string;
  apiKeyPrefix?: string;
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
  private readonly demoEndpoints: DemoEndpointsService;
  private readonly accountRepo: AccountRepository;
  private readonly terminalManager: TerminalManager;
  private readonly source: AgentSource;
  private readonly accountId: string;
  private readonly maxSessions: number;
  private readonly sourceIp?: string;
  private readonly apiKeyLabel?: string;
  private readonly apiKeyPrefix?: string;

  constructor(opts: AgentSessionOptions) {
    this.endpointRepo = opts.endpointRepo;
    this.demoEndpoints = opts.demoEndpoints;
    this.accountRepo = opts.accountRepo;
    this.terminalManager = opts.terminalManager;
    this.source = opts.source;
    this.accountId = opts.accountId;
    this.maxSessions = opts.maxSessions ?? 5;
    this.sourceIp = opts.sourceIp;
    this.apiKeyLabel = opts.apiKeyLabel;
    this.apiKeyPrefix = opts.apiKeyPrefix;
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
    const own = await this.endpointRepo.findAllForAccount(this.accountId);
    const account = await this.accountRepo.findById(this.accountId);
    const merged = account?.showDemoEndpoints
      ? [...own, ...this.demoEndpoints.list(this.accountId)]
      : own;
    return merged.map(({ id, label, host, port, username, description }) => ({
      id,
      label,
      host,
      port,
      username,
      description,
    }));
  }

  async createSession(endpointId: string, reason: string): Promise<TerminalSession> {
    // Ownership check first — a foreign endpoint UUID always returns "Unknown
    // endpoint" regardless of the caller's quota state, so probing can't leak
    // anything about another account's endpoints. Without this scope a caller
    // could pass any endpoint UUID and trigger a WebAuthn approval prompt on
    // the owning account with attacker-chosen reason text — and, if approved,
    // drive the resulting session via send_keys / read_output.
    //
    // Demo endpoints aren't account-scoped (they're a global config set), so
    // route them through the synthesizer instead of the per-account repo.
    const endpoint = isDemoEndpointId(endpointId)
      ? this.demoEndpoints.findById(endpointId, this.accountId)
      : await this.endpointRepo.findByIdForAccount(endpointId, this.accountId);
    if (!endpoint) {
      throw new Error(`Unknown endpoint: ${endpointId}`);
    }
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
      apiKeyLabel: this.apiKeyLabel,
      apiKeyPrefix: this.apiKeyPrefix,
    };
    const session = await this.terminalManager.create(endpoint, this.accountId, trigger);
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
    this.terminalManager.close(sessionId, "client.mcp");
    this.ownedSessions.delete(sessionId);
  }

  /** Close all owned sessions — called on agent disconnect */
  destroy(): void {
    for (const sessionId of this.ownedSessions) {
      try {
        this.terminalManager.close(sessionId, "agent-disconnect");
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
