// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WsClient } from "./ws-client.js";

// Mock WebSocket
class MockWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  static instances: MockWebSocket[] = [];

  readyState = MockWebSocket.OPEN;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  send = vi.fn();
  OPEN = MockWebSocket.OPEN;

  constructor(public url: string) {
    MockWebSocket.instances.push(this);
  }

  simulateMessage(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }

  simulateClose() {
    this.onclose?.();
  }
}

describe("WsClient", () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    vi.stubGlobal("WebSocket", MockWebSocket);
    vi.stubGlobal("location", { protocol: "http:", host: "localhost:3000" });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("connects to the correct WebSocket URL", () => {
    const client = new WsClient();
    client.connect();
    expect(MockWebSocket.instances).toHaveLength(1);
    expect(MockWebSocket.instances[0].url).toBe("ws://localhost:3000/ws");
  });

  it("uses wss for https", () => {
    vi.stubGlobal("location", { protocol: "https:", host: "example.com" });
    const client = new WsClient();
    client.connect();
    expect(MockWebSocket.instances[0].url).toBe("wss://example.com/ws");
  });

  describe("onMessage", () => {
    it("dispatches messages to handlers", () => {
      const client = new WsClient();
      client.connect();
      const handler = vi.fn();
      client.onMessage(handler);

      const msg = { type: "terminal:output", sessionId: "sess_1", data: "hello" };
      MockWebSocket.instances[0].simulateMessage(msg);

      expect(handler).toHaveBeenCalledWith(msg);
    });

    it("supports multiple handlers", () => {
      const client = new WsClient();
      client.connect();
      const h1 = vi.fn();
      const h2 = vi.fn();
      client.onMessage(h1);
      client.onMessage(h2);

      MockWebSocket.instances[0].simulateMessage({ type: "terminal:closed", sessionId: "s1" });

      expect(h1).toHaveBeenCalled();
      expect(h2).toHaveBeenCalled();
    });

    it("returns unsubscribe function", () => {
      const client = new WsClient();
      client.connect();
      const handler = vi.fn();
      const unsub = client.onMessage(handler);

      unsub();
      MockWebSocket.instances[0].simulateMessage({ type: "terminal:closed", sessionId: "s1" });

      expect(handler).not.toHaveBeenCalled();
    });

    it("ignores malformed messages", () => {
      const client = new WsClient();
      client.connect();
      const handler = vi.fn();
      client.onMessage(handler);

      // Directly call onmessage with invalid JSON
      MockWebSocket.instances[0].onmessage?.({ data: "not json" });

      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe("send methods", () => {
    it("sends attach message", () => {
      const client = new WsClient();
      client.connect();
      client.attach("sess_1");

      expect(MockWebSocket.instances[0].send).toHaveBeenCalledWith(
        JSON.stringify({ type: "terminal:attach", sessionId: "sess_1" }),
      );
    });

    it("sends input message", () => {
      const client = new WsClient();
      client.connect();
      client.sendInput("sess_1", "ls\n");

      expect(MockWebSocket.instances[0].send).toHaveBeenCalledWith(
        JSON.stringify({ type: "terminal:input", sessionId: "sess_1", data: "ls\n" }),
      );
    });

    it("sends resize message", () => {
      const client = new WsClient();
      client.connect();
      client.sendResize("sess_1", 120, 40);

      expect(MockWebSocket.instances[0].send).toHaveBeenCalledWith(
        JSON.stringify({ type: "terminal:resize", sessionId: "sess_1", cols: 120, rows: 40 }),
      );
    });

    it("sends close message", () => {
      const client = new WsClient();
      client.connect();
      client.closeSession("sess_1");

      expect(MockWebSocket.instances[0].send).toHaveBeenCalledWith(
        JSON.stringify({ type: "terminal:close", sessionId: "sess_1" }),
      );
    });

    it("does not send when WebSocket is not open", () => {
      const client = new WsClient();
      client.connect();
      MockWebSocket.instances[0].readyState = MockWebSocket.CLOSED;

      client.sendInput("sess_1", "data");
      expect(MockWebSocket.instances[0].send).not.toHaveBeenCalled();
    });

    it("does not send when not connected", () => {
      const client = new WsClient();
      // Don't call connect()
      client.sendInput("sess_1", "data");
      // Should not throw
    });
  });

  describe("reconnect", () => {
    it("reconnects on close", () => {
      vi.useFakeTimers();
      const client = new WsClient();
      client.connect();
      expect(MockWebSocket.instances).toHaveLength(1);

      MockWebSocket.instances[0].simulateClose();
      vi.advanceTimersByTime(2000);

      expect(MockWebSocket.instances).toHaveLength(2);
      vi.useRealTimers();
    });
  });
});
