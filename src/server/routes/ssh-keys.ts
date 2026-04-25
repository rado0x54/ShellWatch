import type { FastifyInstance } from "fastify";
import type { AccountRepository, SshKeyRepository } from "../../db/index.js";
import type { KeyAvailability } from "../../transport/key-directory-watcher.js";

export interface SshKeyRoutesParams {
  app: FastifyInstance;
  keyRepo: SshKeyRepository;
  accountRepo: AccountRepository;
  keyAvailability?: KeyAvailability | null;
}

export function registerSshKeyRoutes(params: SshKeyRoutesParams) {
  const { app, keyRepo, accountRepo, keyAvailability = null } = params;

  app.get("/api/keys", async (request) => {
    const allKeys = await keyRepo.findAll();
    const isAdmin = accountRepo.isAdmin(request.accountId);

    // File-based keys only (passkeys are listed via /api/webauthn/credentials)
    const fileKeys = isAdmin ? allKeys.filter((k) => k.type === "file") : [];

    return {
      keys: fileKeys.map((k) => {
        const available = keyAvailability?.isAvailable(k.fingerprint) ?? true;
        return {
          id: k.id,
          label: k.label,
          type: k.type,
          algorithm: k.publicKey.split(" ")[0] ?? "unknown",
          fingerprint: k.fingerprint,
          revoked: !k.enabled,
          available: k.enabled && available,
          authorizedKeysEntry: k.publicKey ? `${k.publicKey}` : null,
          createdAt: k.createdAt,
          lastUsedAt: k.lastUsedAt,
        };
      }),
    };
  });
}
