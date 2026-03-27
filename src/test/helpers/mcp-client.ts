import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { TestLog } from "./test-log.js";

export interface TestMcpClient {
  client: Client;
  callTool(
    name: string,
    args?: Record<string, unknown>,
  ): Promise<{ content: string; isError?: boolean }>;
  close(): Promise<void>;
}

export async function createTestMcpClient(appUrl: string, log: TestLog): Promise<TestMcpClient> {
  const transport = new StreamableHTTPClientTransport(new URL(`${appUrl}/mcp`));
  const client = new Client({ name: "test-client", version: "1.0.0" });

  await client.connect(transport);
  log.add("mcp-client", "connected");

  return {
    client,
    async callTool(name: string, args: Record<string, unknown> = {}) {
      log.add("mcp-client", `calling tool: ${name}`, args);
      const result = await client.callTool({ name, arguments: args });
      const content = (result.content as { type: string; text: string }[])[0].text;
      log.add("mcp-client", `tool result: ${name}`, { isError: result.isError, content });
      return { content, isError: result.isError as boolean | undefined };
    },
    async close() {
      await client.close();
      log.add("mcp-client", "closed");
    },
  };
}
