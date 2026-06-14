// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { get } from "svelte/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// connectWs() needs a token (else it retries / starts the OAuth flow); stub the
// OAuth layer. Hoisted so individual tests can drive the token / refresh-token
// state for the reconnect-resilience cases.
const oauth = vi.hoisted(() => ({
  getAccessToken: vi.fn(async (): Promise<string | null> => "ui-test-token"),
  hasRefreshToken: vi.fn(() => true),
  beginLogin: vi.fn(async () => {}),
}));
vi.mock("../oauth.js", () => oauth);

import {
  connectWs,
  onWsMessage,
  type SessionListEntry,
  sessions,
  wsAttach,
  wsReleaseControl,
  wsSend,
  wsSendInput,
  wsSendResize,
  wsTakeControl,
} from "./ws.js";

// Mock WebSocket
class MockWebSocket {
  static OPEN = 1;
  static instances: MockWebSocket[] = [];

  url: string;
  readyState = MockWebSocket.OPEN;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  sent: string[] = [];

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  send(data: string) {
    this.sent.push(data);
  }

  simulateMessage(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }
}

describe("ws store", () => {
  let originalWebSocket: typeof globalThis.WebSocket;

  beforeEach(() => {
    sessions.set([]);
    MockWebSocket.instances = [];
    originalWebSocket = globalThis.WebSocket;
    // @ts-expect-error — mock
    globalThis.WebSocket = MockWebSocket;
    // Mock location for connectWs
    vi.stubGlobal("location", {
      protocol: "http:",
      host: "localhost:3000",
      pathname: "/",
      search: "",
    });
    // Default OAuth state: a usable token, a refresh token present.
    oauth.getAccessToken.mockReset().mockResolvedValue("ui-test-token");
    oauth.hasRefreshToken.mockReset().mockReturnValue(true);
    oauth.beginLogin.mockReset();
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
    vi.restoreAllMocks();
  });

  it("connectWs creates a WebSocket connection", async () => {
    await connectWs();
    expect(MockWebSocket.instances).toHaveLength(1);
    expect(MockWebSocket.instances[0].url).toBe("ws://localhost:3000/ws");
  });

  it("sessions:changed updates the sessions store", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];

    const mockSessions: SessionListEntry[] = [
      {
        sessionId: "s1",
        endpointId: "dev",
        status: "open",
        createdAt: "",
        source: "ui",
        mode: "control",
      },
    ];

    ws.simulateMessage({ type: "sessions:changed", sessions: mockSessions });

    expect(get(sessions)).toEqual(mockSessions);
  });

  it("onWsMessage registers a handler and returns unsubscribe", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];

    const received: unknown[] = [];
    const unsub = onWsMessage((msg) => received.push(msg));

    ws.simulateMessage({ type: "terminal:output", sessionId: "s1", data: "hello" });
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ type: "terminal:output", data: "hello" });

    unsub();
    ws.simulateMessage({ type: "terminal:output", sessionId: "s1", data: "after unsub" });
    expect(received).toHaveLength(1);
  });

  it("onWsMessage delivers to multiple handlers", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];

    let count1 = 0;
    let count2 = 0;
    const unsub1 = onWsMessage(() => count1++);
    const unsub2 = onWsMessage(() => count2++);

    ws.simulateMessage({ type: "terminal:closed", sessionId: "s1" });

    expect(count1).toBe(1);
    expect(count2).toBe(1);

    unsub1();
    unsub2();
  });

  it("wsSend sends JSON when connection is open", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];

    wsSend({ type: "test", data: "hello" });

    expect(ws.sent).toHaveLength(1);
    expect(JSON.parse(ws.sent[0])).toEqual({ type: "test", data: "hello" });
  });

  it("wsSend does not send when connection is not open", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];
    ws.readyState = 3; // CLOSED

    wsSend({ type: "test" });

    expect(ws.sent).toHaveLength(0);
  });

  it("wsAttach sends terminal:attach message", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];

    wsAttach("sess-1");

    expect(JSON.parse(ws.sent[0])).toEqual({ type: "terminal:attach", sessionId: "sess-1" });
  });

  it("wsSendInput sends terminal:input message", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];

    wsSendInput("sess-1", "ls\n");

    expect(JSON.parse(ws.sent[0])).toEqual({
      type: "terminal:input",
      sessionId: "sess-1",
      data: "ls\n",
    });
  });

  it("wsSendResize sends terminal:resize message", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];

    wsSendResize("sess-1", 120, 40);

    expect(JSON.parse(ws.sent[0])).toEqual({
      type: "terminal:resize",
      sessionId: "sess-1",
      cols: 120,
      rows: 40,
    });
  });

  it("wsTakeControl sends terminal:take-control message", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];

    wsTakeControl("sess-1");

    expect(JSON.parse(ws.sent[0])).toEqual({ type: "terminal:take-control", sessionId: "sess-1" });
  });

  it("wsReleaseControl sends terminal:release-control message", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];

    wsReleaseControl("sess-1");

    expect(JSON.parse(ws.sent[0])).toEqual({
      type: "terminal:release-control",
      sessionId: "sess-1",
    });
  });

  it("ignores invalid JSON messages", async () => {
    await connectWs();
    const ws = MockWebSocket.instances[0];

    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    ws.onmessage?.({ data: "not json{{{" });

    expect(consoleError).toHaveBeenCalledOnce();
    expect(get(sessions)).toEqual([]);

    consoleError.mockRestore();
  });

  // --- reconnect resilience (F6/F7) ---

  it("retries instead of bouncing to login when the token is gone but a refresh token remains", async () => {
    vi.useFakeTimers();
    oauth.getAccessToken.mockResolvedValue(null);
    oauth.hasRefreshToken.mockReturnValue(true); // transient — Hydra 5xx / offline

    await connectWs();

    expect(MockWebSocket.instances).toHaveLength(0); // no socket opened
    expect(oauth.beginLogin).not.toHaveBeenCalled(); // NOT bounced to login

    vi.clearAllTimers();
    vi.useRealTimers();
  });

  it("sends the user to login when the session is truly gone (no refresh token)", async () => {
    oauth.getAccessToken.mockResolvedValue(null);
    oauth.hasRefreshToken.mockReturnValue(false);

    await connectWs();

    expect(MockWebSocket.instances).toHaveLength(0);
    expect(oauth.beginLogin).toHaveBeenCalledOnce();
  });

  it("reconnect after a drop forces a token refresh", async () => {
    vi.useFakeTimers();
    await connectWs();
    const ws = MockWebSocket.instances[0];

    oauth.getAccessToken.mockClear();
    ws.onclose?.(); // simulate a drop
    await vi.advanceTimersByTimeAsync(2000); // let the scheduled reconnect fire

    expect(oauth.getAccessToken).toHaveBeenCalledWith({ force: true });

    vi.clearAllTimers();
    vi.useRealTimers();
  });
});
