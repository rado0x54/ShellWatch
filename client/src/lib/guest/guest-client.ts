// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * The guest side of a one-time access ticket (#306). Everything here runs on
 * an untrusted device and must behave the same in a logged-in browser: it
 * never reads the SPA's stored tokens, never sends `Authorization`, never
 * opens `/ws`, and stores nothing. The only credentials are the ticket token
 * (from the URL fragment, sent once in the redeem body) and the HttpOnly guest
 * cookie the server sets on redemption (sent automatically on `/ws/guest`).
 */
import type { TerminalSink, TerminalTransport } from "../terminal/transport.js";

/** What the redeem call answers on 202. */
export interface Redeemed {
  confirmationCode: string;
  admissionWindowSeconds: number;
  lifetimeSeconds: number;
  agentForward: boolean;
}

/** Why a redemption failed — mapped from the status code only. */
export type RedeemFailure =
  | "not-found" // unknown, used, expired, revoked: indistinguishable
  | "reason-required"
  | "live-session" // this browser already holds a guest session
  | "busy" // 429: the rate limit; retry later
  | "forbidden"
  | "error";

export type RedeemResult =
  | {
      ok: true;
      redeemed: Redeemed;
      /** Server minus device clock, from the `Date` header (0 if missing). */
      clockOffsetMs: number;
    }
  | { ok: false; failure: RedeemFailure };

/** How far the server's clock is ahead of this device's (ms): server deadlines
 * count down against `Date.now() + offset`. Unparsable gives 0. */
export function clockOffsetMs(serverTime: string | null | undefined, localNow: number): number {
  if (!serverTime) return 0;
  const t = Date.parse(serverTime);
  return Number.isNaN(t) ? 0 : t - localNow;
}

/** Fixed texts for every failure: the server's error bodies are never shown. */
export const REDEEM_FAILURE_TEXT: Record<RedeemFailure, string> = {
  "not-found": "This access link is not valid. It may have been used, revoked or expired.",
  "reason-required": "Please say why you need access.",
  "live-session": "This browser already has an active guest session.",
  // 429 is the owner's guest-session limit or the per-address rate limit;
  // the guest cannot tell which, so the text covers both.
  busy: "Too many requests right now. Try again in a few minutes.",
  forbidden: "This access link cannot be used from here.",
  error: "Something went wrong. Try again.",
};

/** Read the ticket token from the URL fragment and remove it from the address
 * bar at once (not kept in history, gone on reload). */
export function takeTokenFromLocation(
  loc: Pick<Location, "hash" | "pathname" | "search">,
  hist: Pick<History, "replaceState">,
): string | null {
  const raw = loc.hash.startsWith("#") ? loc.hash.slice(1) : loc.hash;
  if (raw) hist.replaceState(null, "", loc.pathname + loc.search);
  const token = raw.trim();
  return /^[A-Za-z0-9_-]{16,128}$/.test(token) ? token : raw ? "" : null;
}

export type CheckResult =
  | { ok: true; reasonRequired: boolean }
  | { ok: false; failure: RedeemFailure };

/** POST /api/tickets/check — whether the link can still be redeemed, without
 * spending it. Only 404/403 are definite; anything else is "error" (the page
 * falls back to the form). */
export async function checkTicket(
  token: string,
  fetchFn: typeof fetch = fetch,
): Promise<CheckResult> {
  let res: Response;
  try {
    res = await fetchFn("/api/tickets/check", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
  } catch {
    return { ok: false, failure: "error" };
  }
  switch (res.status) {
    case 200:
      try {
        const body = (await res.json()) as { reasonRequired?: unknown };
        return { ok: true, reasonRequired: body.reasonRequired === true };
      } catch {
        return { ok: false, failure: "error" };
      }
    case 403:
      return { ok: false, failure: "forbidden" };
    case 404:
      return { ok: false, failure: "not-found" };
    default:
      return { ok: false, failure: "error" };
  }
}

/** POST /api/tickets/redeem — spends the ticket. */
export async function redeemTicket(
  token: string,
  reason: string,
  fetchFn: typeof fetch = fetch,
  /** End this browser's current guest session instead of a 409. */
  replaceCurrent = false,
): Promise<RedeemResult> {
  let res: Response;
  try {
    res = await fetchFn("/api/tickets/redeem", {
      method: "POST",
      // Same-origin cookies only (the server sets the guest cookie); no
      // Authorization header, ever.
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(replaceCurrent ? { token, reason, replaceCurrent } : { token, reason }),
    });
  } catch {
    return { ok: false, failure: "error" };
  }
  switch (res.status) {
    case 202:
      try {
        return {
          ok: true,
          redeemed: (await res.json()) as Redeemed,
          clockOffsetMs: clockOffsetMs(res.headers.get("Date"), Date.now()),
        };
      } catch {
        return { ok: false, failure: "error" };
      }
    case 400:
      return { ok: false, failure: "reason-required" };
    case 403:
      return { ok: false, failure: "forbidden" };
    case 404:
      return { ok: false, failure: "not-found" };
    case 409:
      return { ok: false, failure: "live-session" };
    case 429:
      return { ok: false, failure: "busy" };
    default:
      return { ok: false, failure: "error" };
  }
}

/** A guest WS `status` frame. */
export interface GuestStatus {
  state: "pending" | "open" | "closed";
  code?: string;
  admissionDeadline?: string;
  lifetimeDeadline?: string;
  message?: string;
  /** The server's clock when the frame was built (ISO 8601). */
  serverTime?: string;
}

/** What `/ws/guest` sends: the `/ws` terminal frames plus `status` (#328). */
export type GuestFrame =
  | ({ type: "status" } & GuestStatus)
  | { type: "terminal:output"; sessionId: string; data: string; offset: number; reset?: true }
  | { type: "terminal:closed"; sessionId: string };

export interface GuestSocketHandlers {
  onStatus: (st: GuestStatus) => void;
  /** The socket closed without a final `closed` status (network drop, or
   * the server refused the handshake). */
  onDrop: () => void;
}

type SocketCtor = new (url: string) => WebSocket;

/**
 * The guest WebSocket, and the guest page's terminal transport. The server
 * attaches the connection to the admitted session; the session id comes
 * from the output frames. `connect()` again after a drop reconnects the same
 * guest session. Client → server: terminal:input, terminal:resize, end.
 */
export class GuestSocket implements TerminalTransport {
  private ws: WebSocket | null = null;
  private ended = false;
  private sessionId: string | null = null;
  private sink: TerminalSink | null = null;
  /** Output before the terminal subscribed (the catch-up follows the open
   * status at once); a reset frame replaces it. */
  private held: Array<{ data: string; reset: boolean }> = [];
  /** The last size, sent again once the session id is known. */
  private size: { cols: number; rows: number } | null = null;

  constructor(
    private readonly handlers: GuestSocketHandlers,
    private readonly loc: Pick<Location, "protocol" | "host"> = location,
    private readonly Socket: SocketCtor = WebSocket,
  ) {}

  connect(): void {
    const proto = this.loc.protocol === "https:" ? "wss:" : "ws:";
    // No subprotocol: the bearer sentinel is the owner socket's, never ours.
    const ws = new this.Socket(`${proto}//${this.loc.host}/ws/guest`);
    this.ws = ws;
    ws.onmessage = (event: MessageEvent) => {
      let frame: GuestFrame;
      try {
        frame = JSON.parse(String(event.data)) as GuestFrame;
      } catch {
        return;
      }
      this.onFrame(frame);
    };
    ws.onclose = () => {
      if (this.ws === ws) this.ws = null;
      if (!this.ended) this.handlers.onDrop();
    };
  }

  private onFrame(frame: GuestFrame): void {
    if (frame.type === "status") {
      if (frame.state === "closed") this.ended = true;
      this.handlers.onStatus(frame);
      return;
    }
    if (frame.type !== "terminal:output" && frame.type !== "terminal:closed") return;
    if (this.sessionId === null) {
      this.sessionId = frame.sessionId;
      if (this.size) this.sendResize(this.size.cols, this.size.rows);
    }
    if (frame.sessionId !== this.sessionId) return;
    if (frame.type === "terminal:closed") {
      this.sink?.closed();
      return;
    }
    const reset = frame.reset === true;
    if (this.sink) this.sink.output(frame.data, reset);
    else if (reset) this.held = [{ data: frame.data, reset }];
    else this.held.push({ data: frame.data, reset });
  }

  subscribe(sink: TerminalSink): () => void {
    this.sink = sink;
    for (const o of this.held.splice(0)) sink.output(o.data, o.reset);
    return () => {
      if (this.sink === sink) this.sink = null;
    };
  }

  private send(msg: Record<string, unknown>): void {
    if (this.ws?.readyState === 1) this.ws.send(JSON.stringify(msg));
  }

  sendInput(data: string): void {
    if (this.sessionId) this.send({ type: "terminal:input", sessionId: this.sessionId, data });
  }

  sendResize(cols: number, rows: number): void {
    this.size = { cols, rows };
    if (this.sessionId)
      this.send({ type: "terminal:resize", sessionId: this.sessionId, cols, rows });
  }

  end(): void {
    this.send({ type: "end" });
  }

  close(): void {
    this.ended = true;
    this.ws?.close();
  }
}
