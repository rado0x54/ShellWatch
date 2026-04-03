import { randomBytes, randomUUID } from "node:crypto";
import {
  createDatabase,
  DrizzleAccountRepository,
  DrizzleApiKeyRepository,
  runMigrations,
} from "../db/index.js";
import { hashApiKey } from "../server/auth/api-key-auth.js";

const [, , command, ...args] = process.argv;

const { db, close } = createDatabase();
runMigrations(db);
const repo = new DrizzleApiKeyRepository(db);
const accountRepo = new DrizzleAccountRepository(db);

try {
  switch (command) {
    case "generate": {
      const labelIdx = args.indexOf("--label");
      const label = labelIdx !== -1 ? args[labelIdx + 1] : undefined;
      if (!label) {
        console.error("Usage: manage-keys generate --label <label>");
        process.exit(1);
      }

      const raw = `sw_${randomBytes(24).toString("hex")}`;
      const hash = hashApiKey(raw);
      const prefix = raw.slice(0, 10);

      const adminId = accountRepo.getAdminAccountId();
      if (!adminId) {
        console.error("No admin account found. Start the server first to create one.");
        process.exit(1);
      }

      await repo.create({
        id: randomUUID(),
        accountId: adminId,
        label,
        keyHash: hash,
        keyPrefix: prefix,
        scopes: ["mcp"],
      });

      console.log(`API key created for "${label}":`);
      console.log(`\n  ${raw}\n`);
      console.log("Save this key — it cannot be recovered.");
      break;
    }

    case "list": {
      const keys = await repo.findAll();
      if (keys.length === 0) {
        console.log("No API keys configured.");
        break;
      }
      console.log("API Keys:\n");
      for (const k of keys) {
        const status = k.enabled ? "active" : "revoked";
        console.log(`  ${k.keyPrefix}...  ${k.label}  [${status}]  (${k.createdAt.slice(0, 10)})`);
      }
      break;
    }

    case "revoke": {
      const id = args[0];
      if (!id) {
        console.error("Usage: manage-keys revoke <id>");
        process.exit(1);
      }
      await repo.revoke(id);
      console.log(`Key ${id} revoked.`);
      break;
    }

    default:
      console.log("Usage: manage-keys <generate|list|revoke>");
      console.log("  generate --label <label>   Create a new API key");
      console.log("  list                       List all API keys");
      console.log("  revoke <id>                Revoke an API key");
      process.exit(command ? 1 : 0);
  }
} finally {
  close();
}
