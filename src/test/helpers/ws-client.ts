// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import WebSocket from "ws";
import type { TestLog } from "./test-log.js";

export interface TestWsClient {
  ws: WebSocket;
  /** Wait for a message of a specific type */
  waitForMessage<T = unknown>(type: string, timeout?: number): Promise<T>;
  /** Collect all messages of a type that arrive within a duration */
  collectMessages(type: string, durationMs: number): Promise<unknown[]>;
  /** Send a message */
  send(msg: Record<string, unknown>): void;
  close(): void;
}

interface ParsedMessage {
  type: string;
  [key: string]: unknown;
}

export function connectTestWsClient(
  appUrl: string,
  log: TestLog,
  accessToken?: string,
): Promise<TestWsClient> {
  // Mirror the browser: carry the bearer token in the Sec-WebSocket-Protocol
  // subprotocol alongside the sentinel (#217). The bearer gate reads it there.
  const wsUrl = `${appUrl.replace("http://", "ws://")}/ws`;
  const protocols = accessToken ? ["shellwatch.bearer", accessToken] : undefined;

  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl, protocols);

    // Buffer messages from the start — before "open" fires
    const buffered: ParsedMessage[] = [];
    const waiters: Array<{ type: string; resolve: (msg: ParsedMessage) => void }> = [];

    function dispatch(msg: ParsedMessage) {
      // Check if any waiter wants this message
      const idx = waiters.findIndex((w) => w.type === msg.type);
      if (idx >= 0) {
        const waiter = waiters[idx];
        waiters.splice(idx, 1);
        waiter.resolve(msg);
      } else {
        buffered.push(msg);
      }
    }

    ws.on("message", (raw) => {
      try {
        const msg: ParsedMessage = JSON.parse(raw.toString());
        log.add("ws-client", `received: ${msg.type}`, msg);
        dispatch(msg);
      } catch {
        // ignore malformed
      }
    });

    ws.on("error", (err) => {
      log.add("ws-client", "error", err.message);
      reject(err);
    });

    ws.on("open", () => {
      log.add("ws-client", "connected");

      resolve({
        ws,

        waitForMessage<T = unknown>(type: string, timeout = 5000): Promise<T> {
          // Check buffer first
          const idx = buffered.findIndex((m) => m.type === type);
          if (idx >= 0) {
            const msg = buffered[idx];
            buffered.splice(idx, 1);
            return Promise.resolve(msg as T);
          }

          return new Promise((res, rej) => {
            const timer = setTimeout(() => {
              const wIdx = waiters.findIndex((w) => w.resolve === waiterResolve);
              if (wIdx >= 0) waiters.splice(wIdx, 1);
              rej(new Error(`Timeout waiting for message type "${type}" after ${timeout}ms`));
            }, timeout);

            function waiterResolve(msg: ParsedMessage) {
              clearTimeout(timer);
              res(msg as T);
            }

            waiters.push({ type, resolve: waiterResolve });
          });
        },

        collectMessages(type: string, durationMs: number): Promise<unknown[]> {
          return new Promise((res) => {
            const collected = buffered.filter((m) => m.type === type);
            // Remove collected from buffer
            for (let i = buffered.length - 1; i >= 0; i--) {
              if (buffered[i].type === type) buffered.splice(i, 1);
            }

            function waiterResolve(msg: ParsedMessage) {
              collected.push(msg);
              // Re-register for more
              waiters.push({ type, resolve: waiterResolve });
            }
            waiters.push({ type, resolve: waiterResolve });

            setTimeout(() => {
              const wIdx = waiters.findIndex((w) => w.resolve === waiterResolve);
              if (wIdx >= 0) waiters.splice(wIdx, 1);
              res(collected);
            }, durationMs);
          });
        },

        send(msg: Record<string, unknown>) {
          log.add("ws-client", `sending: ${msg.type}`, msg);
          ws.send(JSON.stringify(msg));
        },

        close() {
          ws.close();
          log.add("ws-client", "closed");
        },
      });
    });
  });
}
