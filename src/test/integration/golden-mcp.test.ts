// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden characterization of the MCP tool surface — the JSON payloads returned
 * inside each tool's text block, and the isError/message shape on failure.
 * Parity oracle for the Go rewrite (#225 item 2). See docs/api/mcp-tools.md for
 * the surface and src/test/helpers/golden.ts for the normalization contract.
 *
 * `shellwatch_read_output` is deliberately NOT goldened by value — the echo
 * shell's banner/prompt output is non-deterministic; only its wrapper shape
 * ({ data, offset, hasMore }) is asserted structurally.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import {
  createTestLog,
  createTestMcpClient,
  expectGolden,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestMcpClient,
  type TestSshServer,
} from "../helpers/index.js";

describe("Golden: MCP contract", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let mcp: TestMcpClient;
  let ports: number[];

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log);
    mcp = await createTestMcpClient(app.url, log, app.apiKey);
    ports = [app.port, sshServer.port];
  });

  afterAll(async () => {
    await mcp?.close();
    await app?.close();
    await sshServer?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  /** Golden a successful tool call by parsing its JSON text block. */
  async function snapTool(name: string, tool: string, args?: Record<string, unknown>) {
    const { content, isError } = await mcp.callTool(tool, args);
    expect(isError, `tool ${tool} unexpectedly errored: ${content}`).toBeFalsy();
    expectGolden(
      import.meta.url,
      name,
      { tool, isError: Boolean(isError), result: JSON.parse(content) },
      { ports },
    );
  }

  /** Golden an errored tool call (content is a plain message, not JSON). */
  async function snapToolError(name: string, tool: string, args?: Record<string, unknown>) {
    const { content, isError } = await mcp.callTool(tool, args);
    expect(isError, `tool ${tool} was expected to error`).toBeTruthy();
    expectGolden(import.meta.url, name, { tool, isError: true, message: content }, { ports });
  }

  it("manage_endpoints list", () =>
    snapTool("mcp-endpoints-list", "shellwatch_manage_endpoints", { action: "list" }));

  it("manage_endpoints read", () =>
    snapTool("mcp-endpoints-read", "shellwatch_manage_endpoints", {
      action: "read",
      id: "test-server",
    }));

  it("manage_endpoints read (not found → isError)", () =>
    snapToolError("mcp-endpoints-read-missing", "shellwatch_manage_endpoints", {
      action: "read",
      id: "nope",
    }));

  it("manage_keys list", () =>
    snapTool("mcp-keys-list", "shellwatch_manage_keys", { action: "list" }));

  it("session lifecycle: create → send_keys → list → close", async () => {
    const created = await mcp.callTool("shellwatch_create_session", {
      endpointId: "test-server",
      reason: "golden characterization run",
    });
    const session = JSON.parse(created.content);
    expectGolden(
      import.meta.url,
      "mcp-create-session",
      { tool: "shellwatch_create_session", isError: false, result: session },
      { ports },
    );

    await snapTool("mcp-send-keys", "shellwatch_send_keys", {
      sessionId: session.sessionId,
      keys: ["text:echo hi", "enter"],
    });

    await snapTool("mcp-list-sessions", "shellwatch_list_sessions");

    // Structural-only assertion for read_output (content is non-deterministic).
    const out = JSON.parse(
      (
        await mcp.callTool("shellwatch_read_output", {
          sessionId: session.sessionId,
        })
      ).content,
    );
    expect(Object.keys(out).sort()).toEqual(["data", "hasMore", "offset"]);
    expect(typeof out.data).toBe("string");
    expect(typeof out.offset).toBe("number");
    expect(typeof out.hasMore).toBe("boolean");

    await snapTool("mcp-close-session", "shellwatch_close_session", {
      sessionId: session.sessionId,
    });
  });
});
