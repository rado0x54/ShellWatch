// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * The guest side of a one-time access ticket (#306). Everything here runs on
 * an untrusted device and must behave the same in a logged-in browser: it
 * never reads the SPA's stored tokens, never sends `Authorization`, never
 * opens `/ws`, and stores nothing. The only credentials are the ticket token
 * (from the URL fragment, sent once in the redeem body) and the HttpOnly guest
 * cookie the server sets on redemption (sent automatically on `/ws/guest`).
 */

/** What the redeem call answers on 202. */
export interface Redeemed {
  confirmationCode: string;
  attachDeadline: string;
  admissionWindowSeconds: number;
  lifetimeSeconds: number;
  agentForward: boolean;
}

/** Why a redemption failed — mapped from the status code only. */
export type RedeemFailure =
  | "not-found" // unknown, used, expired, revoked: indistinguishable
  | "reason-required"
  | "live-session" // this browser already holds a guest session
  | "busy" // the owner's guest-session cap; retry later
  | "forbidden"
  | "error";

export type RedeemResult = { ok: true; redeemed: Redeemed } | { ok: false; failure: RedeemFailure };

/** Fixed texts for every failure: the server's error bodies are never shown. */
export const REDEEM_FAILURE_TEXT: Record<RedeemFailure, string> = {
  "not-found": "This access link is not valid. It may have been used, revoked or expired.",
  "reason-required": "Please say why you need access.",
  "live-session": "This browser already has an active guest session.",
  busy: "Too many guest sessions are active right now. Try again in a few minutes.",
  forbidden: "This access link cannot be used from here.",
  error: "Something went wrong. Try again.",
};

/**
 * Read the ticket token from the URL fragment and remove it from the address
 * bar before anything else happens, so it is not kept in history and does not
 * survive a reload.
 */
export function takeTokenFromLocation(
  loc: Pick<Location, "hash" | "pathname" | "search">,
  hist: Pick<History, "replaceState">,
): string | null {
  const raw = loc.hash.startsWith("#") ? loc.hash.slice(1) : loc.hash;
  if (raw) hist.replaceState(null, "", loc.pathname + loc.search);
  const token = raw.trim();
  return /^[A-Za-z0-9_-]{16,128}$/.test(token) ? token : raw ? "" : null;
}

/** POST /api/tickets/redeem — the guest page's only REST call. */
export async function redeemTicket(
  token: string,
  reason: string,
  fetchFn: typeof fetch = fetch,
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
      body: JSON.stringify({ token, reason }),
    });
  } catch {
    return { ok: false, failure: "error" };
  }
  switch (res.status) {
    case 202:
      try {
        return { ok: true, redeemed: (await res.json()) as Redeemed };
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
  state: "pending" | "refused" | "open" | "closed";
  code?: string;
  admissionDeadline?: string;
  remainingSeconds?: number;
  lifetimeDeadline?: string;
  message?: string;
}

export type GuestFrame =
  | ({ type: "status" } & GuestStatus)
  | { type: "output"; data: string; offset: number; reset?: true };

export interface GuestSocketHandlers {
  onStatus: (st: GuestStatus) => void;
  onOutput: (data: string, reset: boolean) => void;
  /** The socket closed without a final `closed` status (network drop, or
   * the server refused the handshake). */
  onDrop: () => void;
}

type SocketCtor = new (url: string) => WebSocket;

/**
 * The guest WebSocket. The connection is the attachment: there are no
 * attach or detach messages. Client → server: input, resize, end, retry.
 */
export class GuestSocket {
  private ws: WebSocket | null = null;
  private ended = false;

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
      if (frame.type === "status") {
        if (frame.state === "closed") this.ended = true;
        this.handlers.onStatus(frame);
      } else if (frame.type === "output") {
        this.handlers.onOutput(frame.data, frame.reset === true);
      }
    };
    ws.onclose = () => {
      if (this.ws === ws) this.ws = null;
      if (!this.ended) this.handlers.onDrop();
    };
  }

  get isEnded(): boolean {
    return this.ended;
  }

  private send(msg: Record<string, unknown>): void {
    if (this.ws?.readyState === 1) this.ws.send(JSON.stringify(msg));
  }

  input(data: string): void {
    this.send({ type: "input", data });
  }

  resize(cols: number, rows: number): void {
    this.send({ type: "resize", cols, rows });
  }

  retry(): void {
    this.send({ type: "retry" });
  }

  end(): void {
    this.send({ type: "end" });
  }

  close(): void {
    this.ended = true;
    this.ws?.close();
  }
}
