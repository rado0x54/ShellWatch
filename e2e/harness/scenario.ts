// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Per-scenario bootstrap (#244): one fresh server (fresh SQLite, fresh key
 * directory), one seeded admin passkey, the file key + passkey installed on the
 * requested sshd targets, and a real `ui` bearer obtained through Hydra. Every
 * scenario file calls this in `beforeAll` and `stop()` in `afterAll`.
 */
import { SSHD, SSHD_USER, type SshdTarget } from "./env.js";
import { createPasskeyIdentity, type PasskeyIdentity } from "./identity.js";
import { loginWebUi, type CookieJar, type TokenResponse } from "./oauth.js";
import { startServer, type RunningServer, type StartServerOptions } from "./server.js";
import { assertStackUp, installIdentities } from "./sshd.js";
import { Api } from "./clients.js";

export interface Scenario {
  server: RunningServer;
  identity: PasskeyIdentity;
  /** The admin account id (sub of every token minted for `identity`). */
  accountId: string;
  uiTokens: TokenResponse;
  uiToken: string;
  /** Browser-equivalent cookie jar of the admin's web login (remembered Hydra session). */
  jar: CookieJar;
  api: Api;
  /** Create an endpoint through the REST API as the web UI does. Returns its id. */
  createEndpoint(spec: {
    label: string;
    target: SshdTarget;
    username: string;
    agentForward?: boolean;
    userVerification?: "required" | "preferred" | "discouraged";
    description?: string;
  }): Promise<string>;
  stop(): Promise<void>;
}

export interface BootOptions extends Omit<StartServerOptions, "adminPasskeys"> {
  /** sshd targets to install the identities on (must be healthy). */
  targets: SshdTarget[];
}

export async function bootScenario(opts: BootOptions): Promise<Scenario> {
  await assertStackUp(opts.targets);
  const identity = createPasskeyIdentity(`E2E ${opts.scenario}`);
  const server = await startServer({ ...opts, adminPasskeys: [identity] });
  try {
    for (const target of opts.targets) {
      installIdentities(target, {
        fileKeyLine: server.fileKey?.publicKeyLine,
        passkeyLine: identity.openSshLine,
      });
    }
    const { tokens, jar } = await loginWebUi(identity);
    const api = new Api(tokens.access_token);
    const me = await api.get<{ id: string; isAdmin: boolean; error?: string }>("/api/auth/me");
    if (me.status !== 200 || !me.body.isAdmin) {
      throw new Error(
        `expected the seeded admin behind the ui token, got ${me.status} ${JSON.stringify(me.body)}`,
      );
    }
    return {
      server,
      identity,
      accountId: me.body.id,
      uiTokens: tokens,
      uiToken: tokens.access_token,
      jar,
      api,
      async createEndpoint(spec) {
        const res = await api.post<{ id: string; status: string; error?: string }>(
          "/api/endpoints",
          {
            label: spec.label,
            host: SSHD[spec.target].host,
            port: SSHD[spec.target].port,
            username: spec.username,
            ...(spec.agentForward !== undefined && { agentForward: spec.agentForward }),
            ...(spec.userVerification && { userVerification: spec.userVerification }),
            ...(spec.description && { description: spec.description }),
          },
        );
        if (res.status !== 200 || res.body.status !== "created") {
          throw new Error(`POST /api/endpoints → ${res.status} ${JSON.stringify(res.body)}`);
        }
        return res.body.id;
      },
      stop: () => server.stop(),
    };
  } catch (err) {
    await server.stop();
    throw err;
  }
}

export { SSHD, SSHD_USER };
