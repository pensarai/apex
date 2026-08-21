import { tool } from "ai";
import { z } from "zod";
import type {
  ApplicationType,
  EndpointTransport,
  EndpointType,
} from "../../../api/apps";
// Importing through the api barrel would create a circular module load:
// api → offSecAgent → offSecAgent/tools → workspaceApps → api.
import {
  createApp,
  createEndpoint,
  listApps,
  listEndpoints,
  searchApps,
  searchEndpoints,
  updateApp,
  updateEndpoint,
} from "../../../api/apps";
import type { ToolContext } from "./types";
import { workspaceFailure } from "./workspaceFailure";

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
] as const satisfies readonly ApplicationType[];

const ENDPOINT_TYPES = [
  "api-endpoint",
  "web-endpoint",
  "auth-endpoint",
  "database",
  "file-storage",
  "asset",
] as const satisfies readonly EndpointType[];

const ENDPOINT_TRANSPORTS = [
  "http",
  "grpc",
  "grpc_web",
  "connect",
] as const satisfies readonly EndpointTransport[];

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

const updateWorkspaceAppInputSchema = z
  .object({
    applicationId: z.string().min(1).describe("Application UUID to update"),
    name: z
      .string()
      .min(1)
      .nullish()
      .transform((value) => value ?? undefined)
      .optional(),
    description: z
      .string()
      .nullish()
      .transform((value) => value ?? undefined)
      .optional(),
    type: z.enum(APPLICATION_TYPES).nullable().optional(),
    framework: z.string().nullable().optional(),
    domainId: z
      .string()
      .nullable()
      .optional()
      .describe("Domain UUID to link, or null to unlink the domain"),
    disallowedActions: z
      .string()
      .nullable()
      .optional()
      .describe("Replaces the complete disallowed-actions text"),
    toolCallDescription,
  })
  .refine(
    ({ applicationId: _, toolCallDescription: __, ...updates }) =>
      Object.values(updates).some((value) => value !== undefined),
    { message: "Provide at least one application field to update" },
  );

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
  transport: z
    .enum(ENDPOINT_TRANSPORTS)
    .nullish()
    .transform((value) => value ?? undefined)
    .optional()
    .describe("Wire transport; defaults to http when omitted"),
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

const updateWorkspaceEndpointInputSchema = z
  .object({
    endpointId: z.string().min(1).describe("Endpoint UUID to update"),
    applicationId: z
      .string()
      .min(1)
      .nullish()
      .transform((value) => value ?? undefined)
      .optional()
      .describe("New parent application UUID"),
    endpoint: z
      .string()
      .min(1)
      .nullish()
      .transform((value) => value ?? undefined)
      .optional(),
    description: z
      .string()
      .nullish()
      .transform((value) => value ?? undefined)
      .optional(),
    type: z.enum(ENDPOINT_TYPES).nullable().optional(),
    transport: z
      .enum(ENDPOINT_TRANSPORTS)
      .nullish()
      .transform((value) => value ?? undefined)
      .optional()
      .describe("Corrected wire transport"),
    location: z.string().nullable().optional(),
    startLineNumber: z.number().int().min(0).nullable().optional(),
    endLineNumber: z.number().int().min(0).nullable().optional(),
    objectives: z
      .array(z.string())
      .nullish()
      .transform((value) => value ?? undefined)
      .optional()
      .describe("Replaces the endpoint's complete objectives list"),
    authenticationRequired: z
      .object({
        required: z.boolean(),
        details: z.string().nullable().optional(),
      })
      .nullable()
      .optional(),
    businessLogic: z
      .string()
      .nullable()
      .optional()
      .describe("Replaces the complete business-logic text"),
    threatModel: z
      .string()
      .nullable()
      .optional()
      .describe("Replaces the complete threat-model text"),
    toolCallDescription,
  })
  .refine(
    ({ endpointId: _, toolCallDescription: __, ...updates }) =>
      Object.values(updates).some((value) => value !== undefined),
    { message: "Provide at least one endpoint field to update" },
  );

export function listWorkspaceApps(_ctx: ToolContext) {
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

export function createWorkspaceApp(_ctx: ToolContext) {
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

export function updateWorkspaceApp(_ctx: ToolContext) {
  return tool({
    description: `Update one application in the user's authenticated Pensar Console workspace.

Use only when the user explicitly asks to change an existing workspace application, including linking or unlinking a domain. Resolve the application and domain IDs with the read-only workspace tools first. Provide at least one field to update; supplied text fields replace their previous values. Returns the updated application record.`,
    inputSchema: updateWorkspaceAppInputSchema,
    execute: async ({ applicationId, toolCallDescription: _, ...updates }) => {
      try {
        const application = await updateApp(applicationId, updates);
        return { success: true as const, application };
      } catch (error: unknown) {
        return workspaceFailure(error);
      }
    },
  });
}

export function listWorkspaceEndpoints(_ctx: ToolContext) {
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

export function createWorkspaceEndpoint(_ctx: ToolContext) {
  return tool({
    description: `Create one endpoint under an application in the user's authenticated Pensar Console workspace.

Use only when the user explicitly asks to add a workspace endpoint. Set \`transport\` when the endpoint uses gRPC, gRPC-Web, or Connect; omitting it preserves the HTTP default. This performs the requested mutation directly through the running Apex process; it does not call \`document_endpoint\`, add RPC metadata, make a non-HTTP endpoint scan-ready, or launch endpoint threat-model enrichment. Returns the created endpoint record.`,
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

export function updateWorkspaceEndpoint(_ctx: ToolContext) {
  return tool({
    description: `Update one endpoint in the user's authenticated Pensar Console workspace.

Use only when the user explicitly asks to change or repair an existing workspace endpoint, including its wire transport. Resolve the endpoint ID first and provide at least one field to update. Supplied objectives replace the complete objectives list. Transport changes recompute endpoint identity and can return a conflict when the target path and transport already exist; never claim records were merged. This tool does not add RPC metadata or make a non-HTTP endpoint scan-ready. Returns the updated endpoint record.`,
    inputSchema: updateWorkspaceEndpointInputSchema,
    execute: async ({ endpointId, toolCallDescription: _, ...updates }) => {
      try {
        const endpoint = await updateEndpoint(endpointId, updates);
        return { success: true as const, endpoint };
      } catch (error: unknown) {
        return workspaceFailure(error);
      }
    },
  });
}
