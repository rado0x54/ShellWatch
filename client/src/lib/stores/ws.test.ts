import { get } from "svelte/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { basePath } from "./connection.js";
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
    basePath.set("");
    sessions.set([]);
    MockWebSocket.instances = [];
    originalWebSocket = globalThis.WebSocket;
    // @ts-expect-error — mock
    globalThis.WebSocket = MockWebSocket;
    // Mock location for connectWs
    vi.stubGlobal("location", { protocol: "http:", host: "localhost:3000" });
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
    vi.restoreAllMocks();
  });

  it("connectWs creates a WebSocket connection", () => {
    connectWs();
    expect(MockWebSocket.instances).toHaveLength(1);
    expect(MockWebSocket.instances[0].url).toBe("ws://localhost:3000/ws");
  });

  it("connectWs uses basePath", () => {
    basePath.set("/shellwatch");
    connectWs();
    expect(MockWebSocket.instances[0].url).toBe("ws://localhost:3000/shellwatch/ws");
  });

  it("sessions:changed updates the sessions store", () => {
    connectWs();
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

  it("onWsMessage registers a handler and returns unsubscribe", () => {
    connectWs();
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

  it("onWsMessage delivers to multiple handlers", () => {
    connectWs();
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

  it("wsSend sends JSON when connection is open", () => {
    connectWs();
    const ws = MockWebSocket.instances[0];

    wsSend({ type: "test", data: "hello" });

    expect(ws.sent).toHaveLength(1);
    expect(JSON.parse(ws.sent[0])).toEqual({ type: "test", data: "hello" });
  });

  it("wsSend does not send when connection is not open", () => {
    connectWs();
    const ws = MockWebSocket.instances[0];
    ws.readyState = 3; // CLOSED

    wsSend({ type: "test" });

    expect(ws.sent).toHaveLength(0);
  });

  it("wsAttach sends terminal:attach message", () => {
    connectWs();
    const ws = MockWebSocket.instances[0];

    wsAttach("sess-1");

    expect(JSON.parse(ws.sent[0])).toEqual({ type: "terminal:attach", sessionId: "sess-1" });
  });

  it("wsSendInput sends terminal:input message", () => {
    connectWs();
    const ws = MockWebSocket.instances[0];

    wsSendInput("sess-1", "ls\n");

    expect(JSON.parse(ws.sent[0])).toEqual({
      type: "terminal:input",
      sessionId: "sess-1",
      data: "ls\n",
    });
  });

  it("wsSendResize sends terminal:resize message", () => {
    connectWs();
    const ws = MockWebSocket.instances[0];

    wsSendResize("sess-1", 120, 40);

    expect(JSON.parse(ws.sent[0])).toEqual({
      type: "terminal:resize",
      sessionId: "sess-1",
      cols: 120,
      rows: 40,
    });
  });

  it("wsTakeControl sends terminal:take-control message", () => {
    connectWs();
    const ws = MockWebSocket.instances[0];

    wsTakeControl("sess-1");

    expect(JSON.parse(ws.sent[0])).toEqual({ type: "terminal:take-control", sessionId: "sess-1" });
  });

  it("wsReleaseControl sends terminal:release-control message", () => {
    connectWs();
    const ws = MockWebSocket.instances[0];

    wsReleaseControl("sess-1");

    expect(JSON.parse(ws.sent[0])).toEqual({
      type: "terminal:release-control",
      sessionId: "sess-1",
    });
  });

  it("ignores invalid JSON messages", () => {
    connectWs();
    const ws = MockWebSocket.instances[0];

    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    ws.onmessage?.({ data: "not json{{{" });

    expect(consoleError).toHaveBeenCalledOnce();
    expect(get(sessions)).toEqual([]);

    consoleError.mockRestore();
  });
});
