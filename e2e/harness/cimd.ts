// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * A Client ID Metadata Document host for the CIMD scenario (#242).
 *
 * The `client_id` of a CIMD client IS an `https` URL that serves the client's
 * own metadata, so testing the real path needs a real HTTPS origin the server
 * trusts. Two things make that awkward and are handled here:
 *
 * - **Trust.** The document is served with a throwaway CA, pointed at via
 *   `hydra.cimd.extraCaBundlePath`. `SSL_CERT_FILE` would be the obvious hook
 *   but Go ignores it on macOS (`root_unix.go` excludes darwin), so the config
 *   option is the only cross-platform way.
 * - **The SSRF guard.** The host is on loopback, which the fetcher refuses by
 *   default, so the scenario also sets `hydra.cimd.allowLoopbackDocuments`
 *   (draft §8.6 permits that for development and testing only).
 *
 * Certificates come from `openssl`, which the suite already depends on
 * indirectly; `ssh-keygen` is used the same way in identity.ts.
 */
import { execFileSync } from "node:child_process";
import { createServer, type Server } from "node:https";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";

export interface CimdDocument {
  client_id?: string;
  client_name?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  response_types?: string[];
  token_endpoint_auth_method?: string;
  jwks_uri?: string;
  client_uri?: string;
  logo_uri?: string;
  scope?: string;
  [key: string]: unknown;
}

export interface DocumentHost {
  /** The Client Identifier URL — what the client presents as its `client_id`. */
  clientId: string;
  /** PEM path for `hydra.cimd.extraCaBundlePath`. */
  caPath: string;
  /** How many times the server has fetched the document. */
  hits(): number;
  /** Requests seen, for asserting the fetch shape (Accept header, method). */
  requests(): { method: string; accept: string | undefined }[];
  /** Replace the served document (document refresh / material change). */
  setDocument(doc: CimdDocument): void;
  /** Serve a non-document response instead, to exercise the failure paths. */
  setRaw(raw: { status: number; contentType?: string; body: string } | null): void;
  stop(): Promise<void>;
}

/** Generate a CA and a leaf for 127.0.0.1 into dir; returns their paths. */
function generateCerts(dir: string): { caPath: string; certPath: string; keyPath: string } {
  const caPath = join(dir, "ca.pem");
  const caKey = join(dir, "ca.key");
  const certPath = join(dir, "leaf.pem");
  const keyPath = join(dir, "leaf.key");
  const csr = join(dir, "leaf.csr");

  // Written to files rather than passed via process substitution: execFileSync
  // runs no shell, and -addext is not portable across OpenSSL/LibreSSL.
  const caConf = join(dir, "ca.cnf");
  writeFileSync(
    caConf,
    "[req]\ndistinguished_name=dn\n[dn]\n[v3]\n" +
      "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n",
  );
  const leafExt = join(dir, "leaf.ext");
  writeFileSync(
    leafExt,
    "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" +
      "basicConstraints=critical,CA:FALSE\n",
  );

  const openssl = (args: string[]) =>
    execFileSync("openssl", args, { stdio: ["ignore", "pipe", "pipe"] });

  openssl([
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    caKey,
    "-out",
    caPath,
    "-days",
    "2",
    "-subj",
    "/CN=ShellWatch E2E CIMD CA",
    "-config",
    caConf,
    "-extensions",
    "v3",
  ]);
  openssl([
    "req",
    "-new",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    keyPath,
    "-out",
    csr,
    "-subj",
    "/CN=127.0.0.1",
  ]);
  openssl([
    "x509",
    "-req",
    "-in",
    csr,
    "-CA",
    caPath,
    "-CAkey",
    caKey,
    "-out",
    certPath,
    "-days",
    "2",
    "-extfile",
    leafExt,
    "-CAcreateserial",
  ]);
  return { caPath, certPath, keyPath };
}

/**
 * Start the document host. Call before `bootScenario` so `caPath` can be put
 * into the server's config.
 *
 * `path` must satisfy the Client Identifier URL rules (draft §3): a path
 * component, no query, no fragment.
 */
export async function startDocumentHost(
  initial: CimdDocument,
  path = "/.well-known/client.json",
): Promise<DocumentHost> {
  const dir = mkdtempSync(join(tmpdir(), "shellwatch-e2e-cimd-"));
  const { caPath, certPath, keyPath } = generateCerts(dir);

  let doc: CimdDocument = initial;
  let raw: { status: number; contentType?: string; body: string } | null = null;
  let hits = 0;
  const requests: { method: string; accept: string | undefined }[] = [];

  const server: Server = createServer(
    { cert: readFileSync(certPath), key: readFileSync(keyPath) },
    (req, res) => {
      hits++;
      requests.push({ method: req.method ?? "", accept: req.headers.accept });
      if (req.url?.split("?")[0] !== path) {
        res.writeHead(404).end();
        return;
      }
      if (raw) {
        res.writeHead(raw.status, {
          "content-type": raw.contentType ?? "application/json",
        });
        res.end(raw.body);
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(doc));
    },
  );

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const clientId = `https://127.0.0.1:${port}${path}`;
  // The document's own client_id MUST equal the URL it is served from (§4).
  doc = { ...doc, client_id: clientId };

  return {
    clientId,
    caPath,
    hits: () => hits,
    requests: () => [...requests],
    setDocument(next) {
      doc = { client_id: clientId, ...next };
      raw = null;
    },
    setRaw(next) {
      raw = next;
    },
    stop: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
