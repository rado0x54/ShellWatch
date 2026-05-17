// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { timingSafeEqual } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { DemoAuthorizedKeysService } from "./service.js";

export const DEMO_AUTHORIZED_KEYS_PATH = "/demo/authorized-keys";

export interface DemoAuthorizedKeysRouteParams {
  app: FastifyInstance;
  service: DemoAuthorizedKeysService;
  /** Optional bearer the demo container must send. Compared in constant time. */
  sharedSecret?: string;
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function registerDemoAuthorizedKeysRoute(params: DemoAuthorizedKeysRouteParams): void {
  const { app, service, sharedSecret } = params;

  app.get<{ Querystring: { user?: string; type?: string; fingerprint?: string } }>(
    DEMO_AUTHORIZED_KEYS_PATH,
    async (request, reply) => {
      // Shared-secret check (defense in depth on top of the IP allowlist). When
      // configured, *every* request must carry it — including misses — so the
      // endpoint never reveals "no such fingerprint" to an unauthenticated peer.
      if (sharedSecret) {
        const header = request.headers.authorization;
        const offered = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : null;
        if (!offered || !constantTimeEqual(offered, sharedSecret)) {
          reply.status(403);
          return { error: "forbidden" };
        }
      }

      const { user, type, fingerprint } = request.query;
      if (!type || !fingerprint) {
        reply.status(400);
        return { error: "missing required parameters: type, fingerprint" };
      }

      const matches = service.lookup({ type, fingerprint });

      // Per #211 comment: log every request — operator gets a real auth-attempt
      // timeline. `user` is informational (sshd's principal arg), not part of
      // the match. Matched accounts are summarized; the response body is the
      // authoritative list.
      app.log.info(
        {
          demoAuthorizedKeys: true,
          user: user ?? null,
          type,
          fingerprint,
          matched: matches.length > 0,
          matchedAccountIds: matches.map((m) => m.accountId),
        },
        matches.length > 0 ? "demo-authorized-keys hit" : "demo-authorized-keys miss",
      );

      // Always 200, even on miss — sshd treats non-2xx as a soft error and
      // logs "AuthorizedKeysCommand failed". Empty body = no match = clean deny.
      reply.type("text/plain; charset=utf-8");
      if (matches.length === 0) return "";
      // One line per match. Append a `shellwatch:<account>/<credLabel>` comment
      // so operator-side logs (sshd VERBOSE etc.) trace back to the credential
      // — purely informational, sshd ignores comments for auth decisions.
      return (
        matches
          .map((m) => `${m.publicKeyOpenSsh} shellwatch:${m.accountId}/${m.credentialId}`)
          .join("\n") + "\n"
      );
    },
  );
}
