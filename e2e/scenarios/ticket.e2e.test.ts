// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * One-time access tickets (#306) end to end: the owner mints a ticket for a
 * file-key endpoint; a headless guest (no bearer, only the ticket and then the
 * guest cookie) redeems it, attaches /ws/guest and waits; the owner's /ws gets
 * the normal endpoint-auth key-approve prompt carrying the ticket trigger and
 * the guest's confirmation code. Skipping it refuses the attempt, Ask again
 * raises a fresh prompt, approving it admits the guest onto the real sshd,
 * and End closes everything and kills the cookie.
 */
import WebSocket from "ws";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SERVER_URL, SSHD_USER, sshdTargets } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import {
  approveSignRequest,
  connectWs,
  denySignRequest,
  type SignRequestFrame,
  type WsClient,
} from "../harness/clients.js";
import { recordScenario } from "../harness/out.js";
import { sleep, stripAnsi, waitFor } from "../harness/util.js";

const target = sshdTargets()[0]!;
const COOKIE = "__Host-sw_guest";

interface GuestFrame {
  type: string;
  state?: string;
  code?: string;
  message?: string;
  remainingSeconds?: number;
  retryAt?: string;
  attemptsLeft?: number;
  data?: string;
  reset?: boolean;
}

/** A headless guest browser: Origin is the external URL, no Authorization. */
class Guest {
  readonly frames: GuestFrame[] = [];
  private ws: WebSocket | null = null;
  private consumed = 0;
  cookie = "";

  async redeem(token: string, reason: string, origin = SERVER_URL) {
    const res = await fetch(`${SERVER_URL}/api/tickets/redeem`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin,
        ...(this.cookie && { cookie: `${COOKIE}=${this.cookie}` }),
      },
      body: JSON.stringify({ token, reason }),
    });
    const setCookie = res.headers.get("set-cookie") ?? "";
    const m = setCookie.match(new RegExp(`${COOKIE}=([^;]+)`));
    if (m) this.cookie = m[1]!;
    return { status: res.status, body: (await res.json()) as Record<string, unknown>, setCookie };
  }

  async check(token: string, origin = SERVER_URL) {
    const res = await fetch(`${SERVER_URL}/api/tickets/check`, {
      method: "POST",
      headers: { "content-type": "application/json", origin },
      body: JSON.stringify({ token }),
    });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  }

  attach(origin = SERVER_URL): Promise<number> {
    return new Promise((resolve) => {
      const ws = new WebSocket(`${SERVER_URL.replace("http://", "ws://")}/ws/guest`, {
        origin,
        headers: this.cookie ? { cookie: `${COOKIE}=${this.cookie}` } : {},
      });
      ws.on("message", (raw) => this.frames.push(JSON.parse(String(raw)) as GuestFrame));
      ws.once("open", () => {
        this.ws = ws;
        resolve(101);
      });
      ws.once("unexpected-response", (_req, res) => resolve(res.statusCode ?? 0));
      ws.once("error", () => resolve(0));
    });
  }

  send(msg: Record<string, unknown>) {
    this.ws?.send(JSON.stringify(msg));
  }

  async status(state: string, timeoutMs = 20_000): Promise<GuestFrame> {
    return waitFor(
      () => {
        for (let i = this.consumed; i < this.frames.length; i++) {
          const f = this.frames[i]!;
          if (f.type === "status" && f.state === state) {
            this.consumed = i + 1;
            return f;
          }
        }
        return null;
      },
      { timeoutMs, what: `guest status ${state}` },
    );
  }

  output(): string {
    return stripAnsi(
      this.frames
        .filter((f) => f.type === "output")
        .map((f) => f.data ?? "")
        .join(""),
    );
  }

  close() {
    this.ws?.close();
  }
}

describe(`one-time access ticket on sshd-${target}`, () => {
  let sc: Scenario;
  let ws: WsClient;
  let endpointId: string;
  const rec = recordScenario(`ticket-${target}`, () => sc?.server);

  beforeAll(async () => {
    sc = await bootScenario({ scenario: `ticket-${target}`, targets: [target] });
    ws = await connectWs(sc.uiToken);
    endpointId = await sc.createEndpoint({
      label: "E2E ticket",
      target,
      username: SSHD_USER.fileKey,
      agentForward: true,
    });
  });

  afterAll(async () => {
    ws?.close();
    await sc?.stop();
  });

  const nextPrompt = () => ws.next<SignRequestFrame>("sign:request", { timeoutMs: 20_000 });

  it("admits a guest only through the owner's approval, on the real sshd", async () => {
    const minted = await sc.api.post<{ ticket: { id: string }; token: string }>(
      `/api/endpoints/${endpointId}/tickets`,
      { label: "Printer fix" },
    );
    expect(minted.status, JSON.stringify(minted.body)).toBe(201);
    const { token } = minted.body;
    const ticketId = minted.body.ticket.id;

    const guest = new Guest();
    // The page checks the link first: valid, reason required, not spent.
    expect(await guest.check(token)).toEqual({ status: 200, body: { reasonRequired: true } });
    // A foreign origin cannot redeem (login CSRF) and the ticket survives it.
    expect((await guest.redeem(token, "x", "http://evil.example")).status).toBe(403);
    const redeemed = await guest.redeem(token, "fix the printer");
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(202);
    expect(redeemed.setCookie).toMatch(/HttpOnly/i);
    expect(redeemed.setCookie).toMatch(/SameSite=Strict/i);
    expect(redeemed.setCookie).toMatch(/Secure/i);
    const code = redeemed.body.confirmationCode as string;
    expect(code).toMatch(/^[2-9A-HJ-NP-Z]{4}$/);
    // Nothing in the redeem response names the endpoint.
    expect(JSON.stringify(redeemed.body)).not.toMatch(/E2E ticket|filekey|sshd/);
    // Spent: redeem and check both answer the uniform 404.
    expect((await new Guest().redeem(token, "again")).status).toBe(404);
    expect((await guest.check(token)).status).toBe(404);

    // Attach: pending with the code, and only now the owner is prompted.
    expect(await guest.attach("http://evil.example")).toBe(403);
    expect(await guest.attach()).toBe(101);
    expect((await guest.status("pending")).code).toBe(code);

    const first = await nextPrompt();
    expect(first.actionType).toBe("key-approve");
    const view = await sc.api.get<{
      context: { trigger: Record<string, unknown> };
    }>(`/api/actions/${first.actionId}`);
    expect(view.body.context.trigger).toMatchObject({
      kind: "ticket",
      reason: "fix the printer",
      ticketId,
      ticketLabel: "Printer fix",
      channel: "web",
      confirmationCode: code,
      agentForward: false,
      lifetimeSeconds: 900,
    });

    // Skip every key: the attempt ends, the guest may ask again.
    await denySignRequest(sc.api, first);
    const refused = await guest.status("refused", 30_000);
    expect(refused.message).toBe("Access was not granted.");
    expect(refused.remainingSeconds).toBeGreaterThan(0);
    expect(JSON.stringify(guest.frames)).not.toMatch(/E2E ticket|filekey|authentication/);

    // Ask again, once the cooldown has passed: a fresh prompt with the same
    // code; approve it.
    expect(refused.attemptsLeft).toBe(2);
    // (+20 ms: timers are not exact, and an early retry is silently ignored.)
    await sleep(Math.max(0, Date.parse(refused.retryAt!) - Date.now()) + 20);
    guest.send({ type: "retry" });
    await guest.status("pending");
    const second = await nextPrompt();
    expect(second.actionId).not.toBe(first.actionId);
    const approved = await approveSignRequest(sc.api, second, null);
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    await guest.status("open", 30_000);

    // A real shell round-trip as the guest.
    await waitFor(() => /\$ ?$/m.test(guest.output()), { timeoutMs: 15_000, what: "prompt" });
    guest.send({ type: "input", data: "echo guest-$((40 + 2))\n" });
    await waitFor(() => guest.output().includes("guest-42"), { timeoutMs: 15_000, what: "echo" });

    // The owner sees the guest session in the normal list.
    const sessions = await sc.api.get<{ sessions: Record<string, unknown>[] }>("/api/sessions");
    const sess = sessions.body.sessions.find((s) => s.source === "ticket");
    expect(sess).toMatchObject({ ticketId, ticketLabel: "Printer fix", guestAttached: true });

    // End: closed for good; the cookie no longer attaches.
    guest.send({ type: "end" });
    expect((await guest.status("closed")).message).toBe("The session has ended.");
    guest.close();
    await waitFor(
      async () => {
        const s = await sc.api.get<{ sessions: { source: string }[] }>("/api/sessions");
        return !s.body.sessions.some((x) => x.source === "ticket");
      },
      { what: "guest session gone" },
    );
    expect(await guest.attach()).toBe(404);

    const audit = await sc.api.get<{ rows: { event: string; endReason: string | null }[] }>(
      `/api/audit/tickets?ticketId=${ticketId}`,
    );
    const events = audit.body.rows.map((r) => r.event).reverse();
    expect(events).toEqual([
      "minted",
      "redeemed",
      "attached",
      "attempt-failed",
      "retried",
      "admitted",
      "ended",
    ]);
    expect(audit.body.rows[0]!.endReason).toBe("client.guest");
    rec.note(`ticket ${ticketId}: ${events.join(" → ")}`);
  });

  it("revoking from the prompt ends a waiting guest at once", async () => {
    const minted = await sc.api.post<{ ticket: { id: string }; token: string }>(
      `/api/endpoints/${endpointId}/tickets`,
      { reasonRequired: false },
    );
    const guest = new Guest();
    expect((await guest.redeem(minted.body.token, "")).status).toBe(202);
    expect(await guest.attach()).toBe(101);
    const prompt = await nextPrompt();
    expect((await sc.api.delete(`/api/tickets/${minted.body.ticket.id}`)).status).toBe(200);
    expect((await guest.status("closed")).message).toBe("Access was not granted.");
    await waitFor(
      async () =>
        (await sc.api.get<{ status: string }>(`/api/actions/${prompt.actionId}`)).status !== 200 ||
        (await sc.api.get<{ status: string }>(`/api/actions/${prompt.actionId}`)).body.status !==
          "pending",
      { what: "prompt cancelled" },
    );
    guest.close();
  });
});
