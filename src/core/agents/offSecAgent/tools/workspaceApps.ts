import { tool } from "ai";
import { z } from "zod";
// Importing through the api barrel would create a circular module load:
// api → offSecAgent → offSecAgent/tools → workspaceApps → api.
import {
  createApp,
  createEndpoint,
  listApps,
  listEndpoints,
  searchApps,
  searchEndpoints,
} from "../../../api/apps";
import type { ToolContext } from "./types";

const APPLICATION_TYPES = [
  "ui",
  "api-service",
  "web-application",
  "full-stack",
  "domain",
  "subdomain",
  "database",
  "cloud-resource",
  "storage",
] as const;

const ENDPOINT_TYPES = [
  "api-endpoint",
  "web-endpoint",
  "auth-endpoint",
  "database",
  "file-storage",
  "asset",
] as const;

const toolCallDescription = z
  .string()
  .describe("A concise description of the workspace operation");

const listWorkspaceAppsInputSchema = z.object({
  query: z
    .string()
    .min(1)
    .optional()
    .describe("Optional substring to search for in application names"),
  limit: z.number().int().min(1).max(200).default(50),
  offset: z.number().int().min(0).default(0),
  toolCallDescription,
});

const createWorkspaceAppInputSchema = z.object({
  name: z.string().min(1).describe("Application name"),
  description: z.string().describe("Application description"),
  type: z.enum(APPLICATION_TYPES).optional(),
  framework: z.string().optional(),
  domainId: z.string().optional().describe("Linked domain UUID"),
  disallowedActions: z.string().optional(),
  toolCallDescription,
});

const listWorkspaceEndpointsInputSchema = z.object({
  applicationId: z.string().min(1).describe("Parent application UUID"),
  query: z
    .string()
    .min(1)
    .optional()
    .describe("Optional substring to search for in endpoint paths"),
  type: z.enum(ENDPOINT_TYPES).optional(),
  minRiskScore: z.number().min(0).max(10).optional(),
  limit: z.number().int().min(1).max(200).default(50),
  offset: z.number().int().min(0).default(0),
  toolCallDescription,
});

const createWorkspaceEndpointInputSchema = z.object({
  applicationId: z.string().min(1).describe("Parent application UUID"),
  endpoint: z.string().min(1).describe("Endpoint path, URL, or route"),
  description: z.string().describe("Endpoint description"),
  type: z.enum(ENDPOINT_TYPES).optional(),
  location: z.string().optional().describe("Source file path"),
  startLineNumber: z.number().int().min(0).optional(),
  endLineNumber: z.number().int().min(0).optional(),
  objectives: z.array(z.string()).optional(),
  authenticationRequired: z
    .object({
      required: z.boolean(),
      details: z.string().nullable().optional(),
    })
    .optional(),
  businessLogic: z.string().optional(),
  threatModel: z.string().optional(),
  toolCallDescription,
});

function workspaceFailure(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return {
    success: false as const,
    error: message,
    recovery: message.includes("Not authenticated")
      ? "Ask the user to run `/login` in Apex (or the local checkout's `bun src/cli.ts login`), then retry this tool."
      : "Report the API error and do not claim the workspace was updated.",
  };
}

export function listWorkspaceApps(ctx: ToolContext) {
  return tool({
    description: `List or search applications in the user's authenticated Pensar Console workspace.

Use this before creating workspace records to resolve application IDs and avoid duplicates. This calls the Console API from the running Apex process, so it works when Apex is launched from source with \`bun run dev\`. Returns application summaries and pagination metadata.`,
    inputSchema: listWorkspaceAppsInputSchema,
    execute: async ({ query, limit, offset }) => {
      try {
        const result = query
          ? await searchApps(query, { limit, offset })
          : await listApps({ limit, offset });
        return { success: true as const, ...result };
      } catch (error: unknown) {
        return workspaceFailure(error);
      }
    },
  });
}

export function createWorkspaceApp(ctx: ToolContext) {
  return tool({
    description: `Create one application in the user's authenticated Pensar Console workspace.

Use only when the user explicitly asks to add a workspace application. This performs the requested mutation directly through the running Apex process; it does not run reconnaissance, create session artifacts, or generate a threat model. Returns the created application record.`,
    inputSchema: createWorkspaceAppInputSchema,
    execute: async ({ toolCallDescription: _, ...data }) => {
      try {
        const application = await createApp(data);
        return { success: true as const, application };
      } catch (error: unknown) {
        return workspaceFailure(error);
      }
    },
  });
}

export function listWorkspaceEndpoints(ctx: ToolContext) {
  return tool({
    description: `List or search endpoints in an application in the user's authenticated Pensar Console workspace.

Use this before creating workspace endpoints to identify existing records and avoid duplicates. This calls the Console API from the running Apex process. Returns endpoint summaries and pagination metadata.`,
    inputSchema: listWorkspaceEndpointsInputSchema,
    execute: async ({
      applicationId,
      query,
      type,
      minRiskScore,
      limit,
      offset,
    }) => {
      try {
        const result = query
          ? await searchEndpoints(query, {
              applicationId,
              type,
              minRiskScore,
              limit,
              offset,
            })
          : await listEndpoints(applicationId, {
              type,
              minRiskScore,
              limit,
              offset,
            });
        return { success: true as const, ...result };
      } catch (error: unknown) {
        return workspaceFailure(error);
      }
    },
  });
}

export function createWorkspaceEndpoint(ctx: ToolContext) {
  return tool({
    description: `Create one endpoint under an application in the user's authenticated Pensar Console workspace.

Use only when the user explicitly asks to add a workspace endpoint. This performs the requested mutation directly through the running Apex process; it does not call \`document_endpoint\` or launch endpoint threat-model enrichment. Returns the created endpoint record.`,
    inputSchema: createWorkspaceEndpointInputSchema,
    execute: async ({ applicationId, toolCallDescription: _, ...data }) => {
      try {
        const endpoint = await createEndpoint(applicationId, data);
        return { success: true as const, endpoint };
      } catch (error: unknown) {
        return workspaceFailure(error);
      }
    },
  });
}
