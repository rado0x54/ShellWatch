// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Wire clients for the e2e suite (#244): a bearer-authenticated REST wrapper,
 * a WebSocket client that keeps every frame (so output can be accumulated per
 * session while sign requests are watched concurrently), the official MCP SDK
 * client (e2e/lib/mcp-client.ts), and the human-in-the-loop approval
 * helpers that stand in for the /sign/:id page.
 */
import WebSocket from "ws";
import { createTestLog, type TestLog } from "../lib/test-log.js";
import { createTestMcpClient, type TestMcpClient } from "../lib/mcp-client.js";
import { SERVER_URL } from "./env.js";
import { signSshChallenge, type PasskeyIdentity } from "./identity.js";
import type { CeremonyOverrides } from "../lib/fake-authenticator.js";
import { stripAnsi, waitFor } from "./util.js";

// ---------------------------------------------------------------------------
// REST
// ---------------------------------------------------------------------------

/** JSON when it parses, `{ raw }` otherwise, `null` for an empty body. */
function parseLoose(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

export interface ApiResponse<T = Record<string, unknown>> {
  status: number;
  body: T;
  headers: Headers;
}

export class Api {
  constructor(
    readonly token: string | null,
    readonly baseUrl: string = SERVER_URL,
  ) {}

  async request<T = Record<string, unknown>>(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {},
  ): Promise<ApiResponse<T>> {
    const headers: Record<string, string> = { ...extraHeaders };
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    return { status: res.status, body: parseLoose(text) as T, headers: res.headers };
  }

  get<T = Record<string, unknown>>(path: string, headers?: Record<string, string>) {
    return this.request<T>("GET", path, undefined, headers);
  }
  post<T = Record<string, unknown>>(
    path: string,
    body?: unknown,
    headers?: Record<string, string>,
  ) {
    return this.request<T>("POST", path, body, headers);
  }
  put<T = Record<string, unknown>>(path: string, body?: unknown) {
    return this.request<T>("PUT", path, body);
  }
  delete<T = Record<string, unknown>>(path: string, headers?: Record<string, string>) {
    return this.request<T>("DELETE", path, undefined, headers);
  }
}

// ---------------------------------------------------------------------------
// WebSocket (/ws)
// ---------------------------------------------------------------------------

export interface WsFrame {
  type: string;
  [key: string]: unknown;
}

export interface SignRequestFrame extends WsFrame {
  type: "sign:request";
  actionId: string;
  actionType: "webauthn-sign" | "key-approve";
  source: "endpoint-auth" | "agent-forwarding" | "agent-proxy";
  deepLink: string;
  endpointLabel?: string;
  endpointAddress?: string;
  challenge?: string;
  credentialId?: string;
  rpId?: string;
  passkeyLabel?: string;
  keyLabel?: string;
  keyFingerprint?: string;
}

export interface SessionListEntry {
  sessionId: string;
  endpointId: string;
  status: string;
  createdAt: string;
  source: string;
  mode: string;
}

export interface WsClient {
  readonly frames: WsFrame[];
  send(frame: Record<string, unknown>): void;
  /** Wait for the next frame of `type` (optionally matching `pred`) that has not been handed out before. */
  next<T extends WsFrame = WsFrame>(
    type: string,
    opts?: { pred?: (f: T) => boolean; timeoutMs?: number },
  ): Promise<T>;
  /** All output received so far for a session, ANSI-stripped. */
  output(sessionId: string): string;
  /** Wait until the session's accumulated output matches. Returns the full text. */
  waitForOutput(sessionId: string, pattern: RegExp | string, timeoutMs?: number): Promise<string>;
  attach(sessionId: string): Promise<{ status: string }>;
  type(sessionId: string, data: string): void;
  /** Latest `sessions:changed` snapshot. */
  sessions(): SessionListEntry[];
  close(): void;
}

/** Connect to /ws the way the browser does: bearer in the subprotocol. */
export function connectWs(token: string): Promise<WsClient> {
  const url = `${SERVER_URL.replace("http://", "ws://")}/ws`;
  const ws = new WebSocket(url, ["shellwatch.bearer", token]);
  const frames: WsFrame[] = [];
  const outputs = new Map<string, string>();
  const consumed = new WeakSet<WsFrame>();
  const listeners = new Set<() => void>();

  ws.on("message", (raw) => {
    let frame: WsFrame;
    try {
      frame = JSON.parse(raw.toString()) as WsFrame;
    } catch {
      return;
    }
    frames.push(frame);
    if (frame.type === "terminal:output") {
      const sid = frame.sessionId as string;
      const prev = frame.reset ? "" : (outputs.get(sid) ?? "");
      outputs.set(sid, prev + (frame.data as string));
    }
    for (const l of listeners) l();
  });

  const onChange = (): Promise<void> =>
    new Promise((r) => {
      const l = () => {
        listeners.delete(l);
        r();
      };
      listeners.add(l);
    });

  const client: WsClient = {
    frames,
    send(frame) {
      ws.send(JSON.stringify(frame));
    },
    async next<T extends WsFrame>(
      type: string,
      opts: { pred?: (f: T) => boolean; timeoutMs?: number } = {},
    ) {
      const { pred, timeoutMs = 10_000 } = opts;
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        const hit = frames.find(
          (f) => f.type === type && !consumed.has(f) && (!pred || pred(f as T)),
        );
        if (hit) {
          consumed.add(hit);
          return hit as T;
        }
        const remaining = deadline - Date.now();
        if (remaining <= 0)
          throw new Error(`timed out after ${timeoutMs}ms waiting for ws frame "${type}"`);
        await Promise.race([
          onChange(),
          new Promise((r) => setTimeout(r, Math.min(remaining, 250))),
        ]);
      }
    },
    output(sessionId) {
      return stripAnsi(outputs.get(sessionId) ?? "");
    },
    waitForOutput(sessionId, pattern, timeoutMs = 15_000) {
      const re =
        typeof pattern === "string"
          ? new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
          : pattern;
      return waitFor(
        () => {
          const text = client.output(sessionId);
          return re.test(text) ? text : null;
        },
        { timeoutMs, intervalMs: 50, what: `session ${sessionId} output to match ${re}` },
      );
    },
    async attach(sessionId) {
      client.send({ type: "terminal:attach", sessionId });
      const status = await client.next<WsFrame & { status: string }>("terminal:status", {
        pred: (f) => f.sessionId === sessionId,
      });
      return { status: status.status };
    },
    type(sessionId, data) {
      client.send({ type: "terminal:input", sessionId, data });
    },
    sessions() {
      const last = [...frames].reverse().find((f) => f.type === "sessions:changed");
      return (last?.sessions as SessionListEntry[] | undefined) ?? [];
    },
    close() {
      ws.close();
    },
  };

  return new Promise((resolve, reject) => {
    ws.once("open", () => resolve(client));
    ws.once("unexpected-response", (_req, res) =>
      reject(new Error(`ws upgrade rejected: HTTP ${res.statusCode}`)),
    );
    ws.once("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Human-in-the-loop approvals (what /sign/:id does)
// ---------------------------------------------------------------------------

export interface ApprovalResult {
  request: SignRequestFrame;
  status: number;
  body: Record<string, unknown>;
}

/** Resolve one sign request: key-approve needs no payload; webauthn-sign needs the passkey. */
export async function approveSignRequest(
  api: Api,
  req: SignRequestFrame,
  identity: PasskeyIdentity | null,
  overrides: CeremonyOverrides = {},
): Promise<ApprovalResult> {
  if (req.actionType === "webauthn-sign") {
    if (!identity) throw new Error("webauthn-sign request but no passkey identity to sign with");
    if (!req.challenge) throw new Error("webauthn-sign request without challenge");
    const payload = signSshChallenge(identity, req.challenge, overrides);
    const res = await api.post(`/api/actions/${req.actionId}/resolve`, payload);
    return { request: req, status: res.status, body: res.body };
  }
  const res = await api.post(`/api/actions/${req.actionId}/resolve`, {});
  return { request: req, status: res.status, body: res.body };
}

export async function denySignRequest(api: Api, req: SignRequestFrame): Promise<ApprovalResult> {
  const res = await api.post(`/api/actions/${req.actionId}/deny`);
  return { request: req, status: res.status, body: res.body };
}

/**
 * Run `op` while approving every sign request that arrives on `ws` until it
 * settles. Returns the op's result plus every approval performed, so tests can
 * assert on what the human was asked to approve.
 */
export async function withApprovals<T>(
  ws: WsClient,
  api: Api,
  identity: PasskeyIdentity | null,
  op: () => Promise<T>,
  opts: {
    decide?: (req: SignRequestFrame) => "approve" | "deny" | "ignore";
    overrides?: CeremonyOverrides;
  } = {},
): Promise<{ result: T; approvals: ApprovalResult[] }> {
  const approvals: ApprovalResult[] = [];
  let done = false;
  const pump = (async () => {
    while (!done) {
      let req: SignRequestFrame;
      try {
        req = await ws.next<SignRequestFrame>("sign:request", { timeoutMs: 300 });
      } catch {
        continue;
      }
      const decision = opts.decide?.(req) ?? "approve";
      if (decision === "approve")
        approvals.push(await approveSignRequest(api, req, identity, opts.overrides));
      else if (decision === "deny") approvals.push(await denySignRequest(api, req));
    }
  })();
  try {
    const result = await op();
    return { result, approvals };
  } finally {
    done = true;
    await pump;
  }
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export interface TerminalSessionBody {
  sessionId: string;
  endpointId: string;
  accountId: string;
  status: string;
  createdAt: string;
  source: string;
}

/** `POST /api/sessions` with approvals handled on the given WS. */
export async function openSession(p: {
  api: Api;
  ws: WsClient;
  identity: PasskeyIdentity | null;
  endpointId: string;
  decide?: (req: SignRequestFrame) => "approve" | "deny" | "ignore";
  overrides?: CeremonyOverrides;
}): Promise<{
  response: ApiResponse<TerminalSessionBody & { error?: string }>;
  approvals: ApprovalResult[];
}> {
  const { result, approvals } = await withApprovals(
    p.ws,
    p.api,
    p.identity,
    () =>
      p.api.post<TerminalSessionBody & { error?: string }>("/api/sessions", {
        endpointId: p.endpointId,
      }),
    { decide: p.decide, overrides: p.overrides },
  );
  return { response: result, approvals };
}

/** Type a line into a session and wait for `pattern` in the accumulated output. */
export async function run(
  ws: WsClient,
  sessionId: string,
  line: string,
  pattern: RegExp | string,
  timeoutMs = 15_000,
): Promise<string> {
  ws.type(sessionId, `${line}\n`);
  return ws.waitForOutput(sessionId, pattern, timeoutMs);
}

/** Wait until a shell prompt has shown up in a fresh session (busybox `$ ` or bash `$ `). */
export function waitForPrompt(
  ws: WsClient,
  sessionId: string,
  timeoutMs = 15_000,
): Promise<string> {
  return ws.waitForOutput(sessionId, /\$ ?$/m, timeoutMs);
}

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

export function testLog(): TestLog {
  return createTestLog();
}

export function connectMcp(token: string, log: TestLog = createTestLog()): Promise<TestMcpClient> {
  return createTestMcpClient(SERVER_URL, log, token);
}

/** Raw JSON-RPC POST to /mcp — for asserting the bearer gate without the SDK's retries. */
export async function rawMcpPing(token: string | null, sessionId?: string): Promise<number> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (token) headers.authorization = `Bearer ${token}`;
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const res = await fetch(`${SERVER_URL}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
  });
  await res.text();
  return res.status;
}
