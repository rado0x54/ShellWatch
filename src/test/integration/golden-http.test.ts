// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden characterization of the HTTP surface — discovery docs, REST success
 * envelopes, and the error/status matrix. Parity oracle for the Go rewrite
 * (#225 item 2). See src/test/helpers/golden.ts for the normalization contract.
 *
 * `externalUrl` is pinned to a fixed host here so discovery bodies and the
 * WWW-Authenticate `resource_metadata` hints are stable independent of the
 * per-run listen port.
 */
import { afterAll, afterEach, beforeAll, describe, it, onTestFailed } from "vitest";
import {
  createTestLog,
  expectGolden,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

const EXTERNAL_URL = "https://shellwatch.example";

describe("Golden: HTTP contract", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let baseUrls: string[];
  let ports: number[];

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log);
    baseUrls = [app.url, EXTERNAL_URL];
    ports = [app.port, sshServer.port];
    // Discovery + WWW-Authenticate read externalUrl at request time — pin it.
    app.config.server.externalUrl = EXTERNAL_URL;
  });

  afterAll(async () => {
    await app?.close();
    await sshServer?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  /** Capture {status, body} of an authenticated request. */
  async function snapAuthed(name: string, path: string, init?: RequestInit) {
    const res = await app.fetch(path, init);
    const body = await res.json().catch(() => null);
    expectGolden(
      import.meta.url,
      name,
      { request: { path }, status: res.status, body },
      { baseUrls, ports },
    );
  }

  /** Capture {status, wwwAuthenticate, body} of an UNauthenticated request. */
  async function snapAnon(name: string, path: string) {
    const res = await fetch(`${app.url}${path}`);
    const body = await res.json().catch(() => null);
    expectGolden(
      import.meta.url,
      name,
      {
        request: { path },
        status: res.status,
        wwwAuthenticate: res.headers.get("www-authenticate"),
        body,
      },
      { baseUrls, ports },
    );
  }

  describe("discovery (RFC 8414 / 9728)", () => {
    it("authorization-server metadata", () =>
      snapAnon("discovery-authorization-server", "/.well-known/oauth-authorization-server"));
    it("protected-resource (bare alias → mcp)", () =>
      snapAnon("discovery-protected-resource", "/.well-known/oauth-protected-resource"));
    it("protected-resource/mcp", () =>
      snapAnon("discovery-protected-resource-mcp", "/.well-known/oauth-protected-resource/mcp"));
    it("protected-resource/agent-proxy", () =>
      snapAnon(
        "discovery-protected-resource-agent",
        "/.well-known/oauth-protected-resource/agent-proxy",
      ));
  });

  describe("REST success envelopes", () => {
    it("GET /health", () => snapAnon("health", "/health"));
    it("GET /api/endpoints", () => snapAuthed("endpoints-list", "/api/endpoints"));

    it("POST /api/endpoints (create → generated id)", async () => {
      await snapAuthed("endpoints-create", "/api/endpoints", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label: "Golden Box", host: "golden.example", username: "gold" }),
      });
    });
  });

  describe("error / status matrix", () => {
    it("401 on /api/* without a token", () => snapAnon("err-401-api", "/api/endpoints"));
    it("401 on /mcp carries resource_metadata hint", () => snapAnon("err-401-mcp", "/mcp"));
    it("404 create-session with unknown endpoint", () =>
      snapAuthed("err-404-session-endpoint", "/api/sessions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ endpointId: "does-not-exist" }),
      }));
    it("404 session tail for unknown session", () =>
      snapAuthed("err-404-session-tail", "/api/sessions/sess_deadbeef0000/tail"));
    it("400 endpoint create with invalid userVerification", () =>
      snapAuthed("err-400-endpoint-create", "/api/endpoints", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label: "Bad", host: "h.example", userVerification: "bogus" }),
      }));
    it("400 endpoint create missing required label/host", () =>
      snapAuthed("err-400-endpoint-missing-fields", "/api/endpoints", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ host: "no-label.example" }),
      }));
  });
});
