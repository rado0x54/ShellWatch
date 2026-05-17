// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SshKeyRepository } from "../../db/repositories/key-repo.js";

export function registerKeyTools(mcpServer: McpServer, keyRepo: SshKeyRepository) {
  mcpServer.tool(
    "shellwatch_manage_keys",
    "Manage SSH keys. Keys are auto-discovered from the key directory. Actions: list, read.",
    {
      action: z.enum(["list", "read"]).describe("Action to perform"),
      id: z.string().optional().describe("Key ID (required for read)"),
    },
    async ({ action, id }) => {
      try {
        switch (action) {
          case "list": {
            const all = await keyRepo.findAll();
            const result = all.map(({ id, label, type, fingerprint }) => ({
              id,
              label,
              type,
              fingerprint,
            }));
            return { content: [{ type: "text", text: JSON.stringify({ keys: result }, null, 2) }] };
          }
          case "read": {
            if (!id) return { isError: true, content: [{ type: "text", text: "id is required" }] };
            const key = await keyRepo.findById(id);
            if (!key)
              return { isError: true, content: [{ type: "text", text: `Key not found: ${id}` }] };
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      id: key.id,
                      label: key.label,
                      type: key.type,
                      fingerprint: key.fingerprint,
                      publicKey: key.publicKeyOpenSsh,
                    },
                    null,
                    2,
                  ),
                },
              ],
            };
          }
        }
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: (err as Error).message }] };
      }
    },
  );
}
