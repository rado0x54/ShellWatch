// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AccountRepository } from "../../db/repositories/account-repo.js";
import {
  ENDPOINT_DESCRIPTION_MAX_LENGTH,
  type EndpointRepository,
} from "../../db/repositories/endpoint-repo.js";
import type { DemoEndpointsService } from "../../demo-endpoints/index.js";
import { isDemoEndpointId } from "../../demo-endpoints/index.js";

export interface EndpointToolDeps {
  endpointRepo: EndpointRepository;
  demoEndpoints: DemoEndpointsService;
  accountRepo: AccountRepository;
  accountId: string;
}

const DEMO_READ_ONLY_ERROR =
  "Demo endpoints are read-only operator-configured entries. Pick one of the account's own endpoints instead.";

export function registerEndpointTools(mcpServer: McpServer, deps: EndpointToolDeps) {
  const { endpointRepo, demoEndpoints, accountRepo, accountId } = deps;

  mcpServer.tool(
    "shellwatch_manage_endpoints",
    "Manage SSH endpoints. Actions: list, read, create, update, delete.",
    {
      action: z.enum(["list", "read", "create", "update", "delete"]).describe("Action to perform"),
      id: z.string().optional().describe("Endpoint ID (required for read, update, delete)"),
      data: z
        .object({
          label: z.string().optional(),
          host: z.string().optional(),
          port: z.number().optional(),
          username: z.string().optional(),
          description: z
            .string()
            .max(ENDPOINT_DESCRIPTION_MAX_LENGTH)
            .nullable()
            .optional()
            .describe(
              `Free-form context (max ${ENDPOINT_DESCRIPTION_MAX_LENGTH} chars) shown to agents on connect. Pass null to clear.`,
            ),
        })
        .optional()
        .describe("Endpoint data (for create and update)"),
    },
    async ({ action, id, data }) => {
      try {
        switch (action) {
          case "list": {
            const own = await endpointRepo.findAllForAccount(accountId);
            const account = await accountRepo.findById(accountId);
            const merged = account?.showDemoEndpoints
              ? [...own, ...demoEndpoints.list(accountId)]
              : own;
            const result = merged.map(({ id, label, host, port, username, description }) => ({
              id,
              label,
              host,
              port,
              username,
              description,
            }));
            return {
              content: [{ type: "text", text: JSON.stringify({ endpoints: result }, null, 2) }],
            };
          }
          case "read": {
            if (!id) return { isError: true, content: [{ type: "text", text: "id is required" }] };
            // Demo endpoints live outside the per-account table — resolve them
            // via the synthesizer regardless of toggle state so an agent that
            // already knows the id can still inspect it.
            const ep = isDemoEndpointId(id)
              ? demoEndpoints.findById(id, accountId)
              : await endpointRepo.findByIdForAccount(id, accountId);
            if (!ep)
              return {
                isError: true,
                content: [{ type: "text", text: `Endpoint not found: ${id}` }],
              };
            return { content: [{ type: "text", text: JSON.stringify(ep, null, 2) }] };
          }
          case "create": {
            if (!id || !data?.label || !data?.host || !data?.username) {
              return {
                isError: true,
                content: [
                  { type: "text", text: "id, data.label, data.host, data.username are required" },
                ],
              };
            }
            if (isDemoEndpointId(id)) {
              return { isError: true, content: [{ type: "text", text: DEMO_READ_ONLY_ERROR }] };
            }
            await endpointRepo.create({
              id,
              accountId,
              label: data.label,
              host: data.host,
              port: data.port ?? 22,
              username: data.username,
              description: data.description ?? null,
            });
            return { content: [{ type: "text", text: JSON.stringify({ status: "created", id }) }] };
          }
          case "update": {
            if (!id || !data)
              return {
                isError: true,
                content: [{ type: "text", text: "id and data are required" }],
              };
            if (isDemoEndpointId(id)) {
              return { isError: true, content: [{ type: "text", text: DEMO_READ_ONLY_ERROR }] };
            }
            await endpointRepo.update(id, accountId, data);
            return { content: [{ type: "text", text: JSON.stringify({ status: "updated", id }) }] };
          }
          case "delete": {
            if (!id) return { isError: true, content: [{ type: "text", text: "id is required" }] };
            if (isDemoEndpointId(id)) {
              return { isError: true, content: [{ type: "text", text: DEMO_READ_ONLY_ERROR }] };
            }
            await endpointRepo.delete(id, accountId);
            return { content: [{ type: "text", text: JSON.stringify({ status: "deleted", id }) }] };
          }
        }
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: (err as Error).message }] };
      }
    },
  );
}
