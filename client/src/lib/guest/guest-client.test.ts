// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { GuestSocket, redeemTicket, takeTokenFromLocation } from "./guest-client.js";

const TOKEN = "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5";

describe("takeTokenFromLocation", () => {
  it("reads the fragment token and removes it from the address bar first", () => {
    const replaceState = vi.fn();
    const token = takeTokenFromLocation(
      { hash: `#${TOKEN}`, pathname: "/t", search: "" },
      { replaceState },
    );
    expect(token).toBe(TOKEN);
    expect(replaceState).toHaveBeenCalledWith(null, "", "/t");
  });

  it("returns null without a fragment and leaves history alone", () => {
    const replaceState = vi.fn();
    expect(takeTokenFromLocation({ hash: "", pathname: "/t", search: "" }, { replaceState })).toBe(
      null,
    );
    expect(replaceState).not.toHaveBeenCalled();
  });

  it("strips and rejects a malformed fragment", () => {
    const replaceState = vi.fn();
    expect(
      takeTokenFromLocation({ hash: "#<script>", pathname: "/t", search: "" }, { replaceState }),
    ).toBe("");
    expect(replaceState).toHaveBeenCalled();
  });
});

describe("redeemTicket", () => {
  it("posts token and reason with same-origin cookies and no Authorization", async () => {
    const fetchFn = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            confirmationCode: "4F7K",
            attachDeadline: "2026-01-01T00:00:30.000Z",
            admissionWindowSeconds: 300,
            lifetimeSeconds: 900,
            agentForward: false,
          }),
          { status: 202 },
        ),
    );
    const res = await redeemTicket(TOKEN, "printer", fetchFn as unknown as typeof fetch);
    expect(res).toMatchObject({ ok: true, redeemed: { confirmationCode: "4F7K" } });
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/tickets/redeem");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("same-origin");
    expect(new Headers(init.headers).has("Authorization")).toBe(false);
    expect(JSON.parse(String(init.body))).toEqual({ token: TOKEN, reason: "printer" });
  });

  it.each([
    [400, "reason-required"],
    [403, "forbidden"],
    [404, "not-found"],
    [409, "live-session"],
    [429, "busy"],
    [500, "error"],
  ])("maps %i to %s without reading the server's text", async (status, failure) => {
    const fetchFn = vi.fn(
      async () => new Response(JSON.stringify({ error: "secret detail" }), { status }),
    );
    expect(await redeemTicket(TOKEN, "", fetchFn as unknown as typeof fetch)).toEqual({
      ok: false,
      failure,
    });
  });
});

class FakeSocket {
  static last: FakeSocket | null = null;
  readyState = 1;
  sent: string[] = [];
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  constructor(
    public url: string,
    public protocols?: string | string[],
  ) {
    FakeSocket.last = this;
  }
  send(data: string) {
    this.sent.push(data);
  }
  close() {
    this.onclose?.();
  }
}

describe("GuestSocket", () => {
  it("connects /ws/guest without a subprotocol and speaks only the guest protocol", () => {
    const statuses: string[] = [];
    const output: string[] = [];
    const drop = vi.fn();
    const s = new GuestSocket(
      { onStatus: (st) => statuses.push(st.state), onOutput: (d) => output.push(d), onDrop: drop },
      { protocol: "https:", host: "sw.example.com" },
      FakeSocket as unknown as new (url: string) => WebSocket,
    );
    s.connect();
    const ws = FakeSocket.last!;
    expect(ws.url).toBe("wss://sw.example.com/ws/guest");
    expect(ws.protocols).toBeUndefined();
    ws.onmessage?.({ data: JSON.stringify({ type: "status", state: "pending", code: "4F7K" }) });
    ws.onmessage?.({ data: JSON.stringify({ type: "status", state: "open" }) });
    ws.onmessage?.({ data: JSON.stringify({ type: "output", data: "hi", offset: 2 }) });
    ws.onmessage?.({ data: JSON.stringify({ type: "sessions:changed", sessions: [] }) });
    s.input("ls\r");
    s.resize(80, 24);
    s.retry();
    s.end();
    expect(statuses).toEqual(["pending", "open"]);
    expect(output).toEqual(["hi"]);
    expect(ws.sent.map((m) => JSON.parse(m).type)).toEqual(["input", "resize", "retry", "end"]);
    ws.onmessage?.({ data: JSON.stringify({ type: "status", state: "closed", message: "x" }) });
    ws.close();
    expect(drop).not.toHaveBeenCalled(); // a final closed status is not a drop
  });

  it("reports a drop when the socket closes without a final status", () => {
    const drop = vi.fn();
    const s = new GuestSocket(
      { onStatus: () => {}, onOutput: () => {}, onDrop: drop },
      { protocol: "http:", host: "localhost:3001" },
      FakeSocket as unknown as new (url: string) => WebSocket,
    );
    s.connect();
    expect(FakeSocket.last!.url).toBe("ws://localhost:3001/ws/guest");
    FakeSocket.last!.close();
    expect(drop).toHaveBeenCalledOnce();
  });
});

// The guest page behaves the same in a logged-in browser: nothing it loads
// can reach the SPA's stored tokens, the bearer-carrying fetch wrapper or the
// owner WebSocket. Pinned on the import graph of the page and its modules.
describe("guest page isolation", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const files = [
    join(here, "guest-client.ts"),
    join(here, "paths.ts"),
    join(here, "../components/GuestTerminal.svelte"),
    join(here, "../../routes/t/+page.svelte"),
  ];
  it.each(files)("%s imports no token, API-wrapper or owner-socket module", (file) => {
    const src = readFileSync(file, "utf8");
    for (const forbidden of [
      "oauth",
      "/api.js",
      "stores/ws",
      "stores/",
      "localStorage",
      "sessionStorage",
      "Authorization",
      "navigator.serviceWorker",
    ]) {
      const hits = src
        .split("\n")
        .filter(
          (l) => l.includes(forbidden) && !l.trim().startsWith("//") && !l.trim().startsWith("*"),
        );
      expect(hits, `${forbidden} in ${file}`).toEqual([]);
    }
  });
});
