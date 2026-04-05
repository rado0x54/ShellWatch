import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { TestLog } from "./test-log.js";

interface NotificationMessage {
  method: string;
  params?: Record<string, unknown>;
}

export interface TestMcpClient {
  client: Client;
  callTool(
    name: string,
    args?: Record<string, unknown>,
  ): Promise<{ content: string; isError?: boolean }>;
  waitForNotification(method: string, timeout?: number): Promise<NotificationMessage>;
  close(): Promise<void>;
}

export async function createTestMcpClient(
  appUrl: string,
  log: TestLog,
  apiKey?: string,
): Promise<TestMcpClient> {
  const transport = new StreamableHTTPClientTransport(new URL(`${appUrl}/mcp`), {
    requestInit: apiKey ? { headers: { authorization: `Bearer ${apiKey}` } } : undefined,
  });
  const client = new Client({ name: "test-client", version: "1.0.0" });

  // Buffer notifications for waitForNotification
  const buffered: NotificationMessage[] = [];
  const waiters: Array<{ method: string; resolve: (msg: NotificationMessage) => void }> = [];

  client.fallbackNotificationHandler = async (notification) => {
    const msg = notification as NotificationMessage;
    log.add("mcp-client", `notification: ${msg.method}`, msg.params);

    const idx = waiters.findIndex((w) => w.method === msg.method);
    if (idx >= 0) {
      const waiter = waiters[idx];
      waiters.splice(idx, 1);
      waiter.resolve(msg);
    } else {
      buffered.push(msg);
    }
  };

  await client.connect(transport);
  log.add("mcp-client", "connected");

  return {
    client,
    async callTool(
      name: string,
      args: Record<string, unknown> = {},
    ): Promise<{ content: string; isError: boolean | undefined }> {
      log.add("mcp-client", `calling tool: ${name}`, args);
      const result = await client.callTool({ name, arguments: args });
      const content = (result.content as { type: string; text: string }[])[0].text;
      log.add("mcp-client", `tool result: ${name}`, { isError: result.isError, content });
      return { content, isError: result.isError as boolean | undefined };
    },
    waitForNotification(method: string, timeout = 5000): Promise<NotificationMessage> {
      // Check buffer first
      const idx = buffered.findIndex((m) => m.method === method);
      if (idx >= 0) {
        const msg = buffered[idx];
        buffered.splice(idx, 1);
        return Promise.resolve(msg);
      }

      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const wIdx = waiters.findIndex((w) => w.resolve === waiterResolve);
          if (wIdx >= 0) waiters.splice(wIdx, 1);
          reject(new Error(`Timeout waiting for MCP notification "${method}" after ${timeout}ms`));
        }, timeout);

        function waiterResolve(msg: NotificationMessage) {
          clearTimeout(timer);
          resolve(msg);
        }

        waiters.push({ method, resolve: waiterResolve });
      });
    },
    async close() {
      await client.close();
      log.add("mcp-client", "closed");
    },
  };
}
