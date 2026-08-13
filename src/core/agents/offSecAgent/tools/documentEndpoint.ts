import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { computeBlackboxRiskScore } from "../../specialized/attackSurface/blackboxRiskScoring";
import {
  EndpointTransportEnum,
  GrpcEndpointMetadataSchema,
} from "../../specialized/attackSurface/grpcSchema";
import { generateThreatModelForEndpoint } from "./threatModelGenerator";
import type { ToolContext } from "./types";

function sanitizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
}

const documentEndpointInputSchema = z.object({
  appName: z
    .string()
    .describe(
      "Name of the parent application this endpoint belongs to. " +
        "Must match the appName used in a prior document_app call.",
    ),
  routePath: z
    .string()
    .describe(
      "The endpoint's unique identity — its HTTP route or access pattern. " +
        "This is the URL path a client requests, NOT a source-file path. " +
        "Examples: '/api/users', '/dashboard', '/auth/login', " +
        "'/{objectKey}?X-Amz-Signature=...', 'arn:aws:s3:::bucket-name'. " +
        "For cloud-resource endpoints (endpointType 'asset') use the specific " +
        "access pattern, not the base domain URL (which is stored on the parent " +
        "application). The route path is the endpoint's display identity — there " +
        "is no separate name field.",
    ),
  endpointType: z
    .enum(["api-endpoint", "web-endpoint", "asset"])
    .describe(
      "Type of endpoint: 'api-endpoint' for REST/GraphQL APIs, " +
        "'web-endpoint' for pages/views, 'asset' for other resources. " +
        "A gRPC method is still 'api-endpoint' — set `transport` to mark it gRPC.",
    ),
  transport: EndpointTransportEnum.optional().describe(
    "Wire transport. Omit or 'http' for normal endpoints. Set 'grpc' " +
      "(or 'grpc_web' / 'connect') for a gRPC method and populate `grpc`.",
  ),
  grpc: GrpcEndpointMetadataSchema.optional().describe(
    "gRPC attributes — required when transport is a gRPC variant. Put the " +
      "wire path '/package.Service/Method' in `routePath`; do not glue on a host.",
  ),
  description: z
    .string()
    .describe("Detailed description of the endpoint including what it does"),
  method: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .describe(
      "HTTP method(s) supported (e.g., 'GET', 'POST', or ['GET', 'POST', 'DELETE']). " +
        "Use 'PAGE' for web pages/views.",
    ),
  handler: z
    .string()
    .optional()
    .describe("Handler function or component name (whitebox analysis)"),
  file: z
    .string()
    .optional()
    .describe(
      "Source-code file where this endpoint is defined, e.g. 'src/routes/users.ts'. " +
        "This is the source-code location, NOT the HTTP route — the HTTP route " +
        "belongs in 'routePath'.",
    ),
  line: z
    .number()
    .optional()
    .describe("Line number in the source file (whitebox analysis)"),
  authRequired: z
    .boolean()
    .optional()
    .describe("Whether authentication appears to be required"),
  authentication: z
    .string()
    .optional()
    .describe("Authentication details if known"),
  riskLevel: z
    .preprocess(
      (val) => {
        if (typeof val === "string") {
          const upper = val.toUpperCase();
          if (upper.includes("CRITICAL")) return "CRITICAL";
          if (upper.includes("HIGH")) return "HIGH";
          if (upper.includes("MEDIUM")) return "MEDIUM";
          if (upper.includes("LOW")) return "LOW";
        }
        return val;
      },
      z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    )
    .describe("Risk level: LOW-CRITICAL (exposed/sensitive)"),
  notes: z
    .string()
    .optional()
    .describe("Additional notes or observations about the endpoint"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing",
    ),
});

type DocumentEndpointInput = z.infer<typeof documentEndpointInputSchema>;

/**
 * Factory for the `document_endpoint` tool.
 *
 * Documents a discovered endpoint during attack surface analysis —
 * writes a JSON file to the session's assets directory (scoped by
 * app name). This tool is specifically for individual endpoints and
 * is designed for incremental creation via the agent log persister in Console.
 */
export function documentEndpoint(ctx: ToolContext) {
  const baseAssetsPath = join(ctx.session.rootPath, "assets");

  return tool({
    description: `Document a discovered endpoint during attack surface analysis.

This stores a session-local reconnaissance artifact and runs endpoint threat-model enrichment. It does NOT create or update an endpoint in the user's authenticated Pensar workspace. Use \`create_workspace_endpoint\` for that mutation.

Endpoints are individual API routes, web pages, or functional paths within an application. Each endpoint belongs to an application (specified by appName).

Use this tool to document:
- API endpoints (e.g., /api/users, /api/orders/:id, /graphql)
- Web pages and views (e.g., /dashboard, /settings, /admin)
- Authentication endpoints (e.g., /login, /auth/callback)
- File upload endpoints, search endpoints, webhook receivers

**API endpoint consolidation:** Do NOT create separate entries for each HTTP method on the same path. Document each unique path ONCE and list all supported methods in \`method\` (e.g., \`["GET", "POST", "DELETE"]\`). Use \`"PAGE"\` for web pages/views.

You MUST specify \`appName\` to associate the endpoint with its parent application (previously documented via \`document_app\`).

Each endpoint creates a JSON file in the assets directory for tracking and analysis.`,
    inputSchema:
      documentEndpointInputSchema as z.ZodType<DocumentEndpointInput>,
    execute: async (input: DocumentEndpointInput) => {
      if (ctx.attackSurfaceRegistry) {
        const assetRecord = {
          appName: input.appName,
          assetName: input.routePath,
          assetType: "endpoint" as const,
          description: input.description,
          details: { url: input.routePath },
        };
        const check = await ctx.attackSurfaceRegistry.register(assetRecord);
        if (check.duplicate) {
          const matchName = check.matchedAsset?.assetName ?? "unknown";
          return {
            success: false,
            duplicate: true,
            matchType: check.matchType,
            matchedAsset: matchName,
            message: `Duplicate endpoint (${check.matchType}): already documented as "${matchName}". Skipping.`,
          };
        }
      }

      if (
        input.routePath.startsWith("https://") ||
        input.routePath.startsWith("http://")
      ) {
        return {
          success: false,
          error: "routePath_is_url",
          message:
            `routePath "${input.routePath}" is a full URL. The domain is already stored on the parent application. ` +
            `Use a path or access pattern instead (e.g. "/api/users", "/{objectKey}?X-Amz-Signature={sig}", "arn:aws:s3:::bucket-name").`,
        };
      }

      const targetDir = join(baseAssetsPath, sanitizeName(input.appName));

      if (!existsSync(targetDir)) {
        mkdirSync(targetDir, { recursive: true });
      }

      const sanitizedPath = sanitizeName(input.routePath);
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = `asset_${sanitizedPath}_${timestamp}.json`;
      const filepath = join(targetDir, filename);

      const heuristicRiskScore = computeBlackboxRiskScore(
        input.riskLevel,
        "endpoint",
        {
          url: input.routePath,
          method: input.method,
          handler: input.handler,
          file: input.file,
          line: input.line,
          authRequired: input.authRequired,
          authentication: input.authentication,
        },
        input.notes,
      );

      const subagentInput = {
        appName: input.appName,
        routePath: input.routePath,
        method: input.method,
        file: input.file,
        line: input.line,
        handler: input.handler,
        authRequired: input.authRequired,
        description: input.description,
        transport: input.transport,
        grpc: input.grpc,
      };

      const threatModelOutput = await generateThreatModelForEndpoint(
        ctx,
        subagentInput,
      );

      const riskScore = threatModelOutput?.riskScore ?? heuristicRiskScore;
      const pentestObjectives = threatModelOutput?.pentestObjectives ?? [];
      const businessLogic = threatModelOutput?.businessLogic;
      const threatModel = threatModelOutput?.threatModel;

      const endpointRecord = {
        ...input,
        pentestObjectives,
        discoveredAt: new Date().toISOString(),
        sessionId: ctx.session.id,
        target: ctx.session.targets[0],
        riskScore,
        ...(businessLogic ? { businessLogic } : {}),
        ...(threatModel ? { threatModel } : {}),
      };

      try {
        writeFileSync(filepath, JSON.stringify(endpointRecord, null, 2));
      } catch (writeError: unknown) {
        if (ctx.attackSurfaceRegistry) {
          await ctx.attackSurfaceRegistry.unregister({
            appName: input.appName,
            assetName: input.routePath,
            assetType: "endpoint",
            description: input.description,
            details: { url: input.routePath },
          });
        }
        throw writeError;
      }

      return {
        success: true,
        appName: input.appName,
        routePath: input.routePath,
        endpointType: input.endpointType,
        transport: input.transport,
        grpc: input.grpc,
        riskLevel: input.riskLevel,
        filepath,
        businessLogic: businessLogic ?? undefined,
        threatModel: threatModel ?? undefined,
        pentestObjectives,
        riskScore,
        message: `Endpoint '${input.routePath}' documented successfully under app '${input.appName}'`,
      };
    },
  });
}
