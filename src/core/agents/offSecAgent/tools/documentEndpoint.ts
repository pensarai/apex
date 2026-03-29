import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import type { ToolContext } from "./types";
import { computeBlackboxRiskScore } from "../../specialized/attackSurface/blackboxRiskScoring";

function sanitizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
}

/**
 * Factory for the `document_endpoint` tool.
 *
 * Documents a discovered endpoint during attack surface analysis —
 * writes a JSON file to the session's assets directory (scoped by
 * app name). This tool is specifically for individual endpoints and
 * is designed for incremental creation via the MessageManager in Console.
 */
export function documentEndpoint(ctx: ToolContext) {
  const baseAssetsPath = join(ctx.session.rootPath, "assets");

  return tool({
    description: `Document a discovered endpoint during attack surface analysis.

Endpoints are individual API routes, web pages, or functional paths within an application. Each endpoint belongs to an application (specified by appName).

Use this tool to document:
- API endpoints (e.g., /api/users, /api/orders/:id, /graphql)
- Web pages and views (e.g., /dashboard, /settings, /admin)
- Authentication endpoints (e.g., /login, /auth/callback)
- File upload endpoints, search endpoints, webhook receivers

**API endpoint consolidation:** Do NOT create separate entries for each HTTP method on the same path. Document each unique path ONCE and list all supported methods in \`method\` (e.g., \`["GET", "POST", "DELETE"]\`). Use \`"PAGE"\` for web pages/views.

You MUST specify \`appName\` to associate the endpoint with its parent application (previously documented via \`document_app\`).

Each endpoint creates a JSON file in the assets directory for tracking and analysis.`,
    inputSchema: z.object({
      appName: z
        .string()
        .describe(
          "Name of the parent application this endpoint belongs to. " +
            "Must match the appName used in a prior document_app call.",
        ),
      endpointName: z
        .string()
        .describe(
          "Unique name for the endpoint — typically the route path " +
            "(e.g., '/api/users', '/dashboard', '/auth/login')",
        ),
      endpointType: z
        .enum(["api-endpoint", "web-endpoint", "asset"])
        .describe(
          "Type of endpoint: 'api-endpoint' for REST/GraphQL APIs, " +
            "'web-endpoint' for pages/views, 'asset' for other resources",
        ),
      description: z
        .string()
        .describe(
          "Detailed description of the endpoint including what it does",
        ),
      routePath: z
        .string()
        .optional()
        .describe(
          "The HTTP route served by this endpoint (e.g., '/api/users', '/dashboard'). " +
            "This is the URL path a client requests — NOT a source-file path. " +
            "Use the separate 'file' field for the source-code location.",
        ),
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
            "This is NOT the HTTP route — use 'routePath' for that.",
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
      pentestObjectives: z
        .array(z.string())
        .describe(
          "Specific pentest objectives for this endpoint — what a pentest agent should test " +
            "(e.g., 'Test for IDOR in /api/orders/{id}')",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async (input) => {
      if (ctx.attackSurfaceRegistry) {
        const assetRecord = {
          appName: input.appName,
          assetName: input.endpointName,
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

      const targetDir = join(baseAssetsPath, sanitizeName(input.appName));

      if (!existsSync(targetDir)) {
        mkdirSync(targetDir, { recursive: true });
      }

      const sanitizedName = sanitizeName(input.endpointName);
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = `asset_${sanitizedName}_${timestamp}.json`;
      const filepath = join(targetDir, filename);

      const riskScore = computeBlackboxRiskScore(
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

      const endpointRecord = {
        ...input,
        discoveredAt: new Date().toISOString(),
        sessionId: ctx.session.id,
        target: ctx.session.targets[0],
        riskScore,
      };

      try {
        writeFileSync(filepath, JSON.stringify(endpointRecord, null, 2));
      } catch (writeError: unknown) {
        if (ctx.attackSurfaceRegistry) {
          await ctx.attackSurfaceRegistry.unregister({
            appName: input.appName,
            assetName: input.endpointName,
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
        endpointName: input.endpointName,
        endpointType: input.endpointType,
        riskLevel: input.riskLevel,
        filepath,
        message: `Endpoint '${input.endpointName}' documented successfully under app '${input.appName}'`,
      };
    },
  });
}
