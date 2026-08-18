import { tool } from "ai";
import { z } from "zod";
// Importing through the api barrel would create a circular module load:
// api → offSecAgent → offSecAgent/tools → workspaceDomains → api.
import { createDomain, listDomains } from "../../../api/domains";
import type { ToolContext } from "./types";
import { workspaceFailure } from "./workspaceFailure";

const toolCallDescription = z
  .string()
  .describe("A concise description of the workspace operation");

const listWorkspaceDomainsInputSchema = z.object({
  toolCallDescription,
});

const createWorkspaceDomainInputSchema = z.object({
  url: z
    .string()
    .min(1)
    .describe("Domain hostname or URL; the scheme may be omitted"),
  toolCallDescription,
});

export function listWorkspaceDomains(_ctx: ToolContext) {
  return tool({
    description: `List domains in the user's authenticated Pensar Console workspace.

Use this to resolve domain IDs before creating or updating workspace applications. Returns public domain summaries only: ID, canonical URL, and verification status.`,
    inputSchema: listWorkspaceDomainsInputSchema,
    execute: async () => {
      try {
        const result = await listDomains();
        return { success: true as const, ...result };
      } catch (error: unknown) {
        return workspaceFailure(error);
      }
    },
  });
}

export function createWorkspaceDomain(_ctx: ToolContext) {
  return tool({
    description: `Create or resolve one domain in the user's authenticated Pensar Console workspace.

Use only when the user explicitly asks to add a workspace domain. Console canonicalizes the URL and returns the existing record on retries. API-created domains remain unverified and this tool does not start reconnaissance. Returns the canonical domain record.`,
    inputSchema: createWorkspaceDomainInputSchema,
    execute: async ({ url }) => {
      try {
        const domain = await createDomain({ url });
        return { success: true as const, domain };
      } catch (error: unknown) {
        return workspaceFailure(error);
      }
    },
  });
}
