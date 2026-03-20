import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import type { ToolContext } from "./types";
import type { DocumentedAssetRecord } from "../../specialized/attackSurface/schemas";
import { computeBlackboxRiskScore } from "../../specialized/attackSurface/blackboxRiskScoring";

/**
 * Factory for the `document_asset` tool.
 *
 * Documents a discovered asset during attack surface analysis —
 * writes a JSON file to the session's assets directory and fires
 * persistence callbacks if provided.
 */
export function documentAsset(ctx: ToolContext) {
  const assetsPath = join(ctx.session.rootPath, "assets");

  return tool({
    description: `Document a discovered asset during attack surface analysis.

Assets are inventory items discovered during reconnaissance and saved to the session's assets folder.

Use this tool to document:
- Domains and subdomains
- Web applications and APIs
- Infrastructure services (mail, DNS, VPN, databases)
- Cloud resources (S3 buckets, CDN, cloud storage)
- Development assets (dev/staging/test environments, CI/CD, repos)

**API endpoint consolidation:** When documenting API endpoints, do NOT create separate assets for each HTTP method on the same path. Instead, document each unique path as a single asset and list all supported methods in \`details.method\` (e.g., \`["GET", "POST", "DELETE"]\`). For example, \`GET /api/users\` and \`POST /api/users\` should be ONE asset named \`/api/users\` with \`details.method: ["GET", "POST"]\`.

Each asset creates a JSON file in the assets directory for tracking and analysis.`,
    inputSchema: z.object({
      assetName: z
        .string()
        .describe(
          "Unique name for the asset (e.g., 'example.com', 'api.example.com', 'admin-panel')",
        ),
      assetType: z
        .enum([
          "domain",
          "subdomain",
          "web_application",
          "api",
          "admin_panel",
          "infrastructure_service",
          "cloud_resource",
          "development_asset",
          "endpoint",
        ])
        .describe("Type of asset discovered"),
      description: z
        .string()
        .describe(
          "Detailed description of the asset including what it is and why it's relevant",
        ),
      details: z
        .preprocess(
          (val) => {
            if (typeof val === "string") {
              try {
                return JSON.parse(val);
              } catch {
                return {};
              }
            }
            return val;
          },
          z.object({
            url: z.string().optional().describe("URL if applicable"),
            method: z
              .union([z.string(), z.array(z.string())])
              .optional()
              .describe(
                "HTTP method(s) supported by this endpoint (e.g., 'GET', 'POST', or ['GET', 'POST', 'DELETE']). " +
                  "Use this for endpoint-type assets to list ALL methods the endpoint accepts.",
              ),
            ip: z.string().optional().describe("IP address if known"),
            ports: z.array(z.number()).optional().describe("Open ports"),
            services: z
              .array(z.string())
              .optional()
              .describe("Running services (e.g., 'nginx 1.18', 'SSH 8.2')"),
            technology: z
              .array(z.string())
              .optional()
              .describe(
                "Technology stack (e.g., 'Node.js', 'Express', 'MongoDB')",
              ),
            endpoints: z
              .array(z.string())
              .optional()
              .describe("Discovered endpoints for web apps/APIs"),
            authentication: z
              .string()
              .optional()
              .describe("Authentication type if known"),
            status: z
              .union([z.string(), z.number()])
              .optional()
              .describe(
                "Status (active, inactive, redirect, error) or HTTP status code",
              ),
          }),
        )
        .describe("Additional details about the asset"),
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
        .describe("Additional notes or observations about the asset"),
      pentestObjectives: z
        .array(z.string())
        .describe(
          "Specific pentest objectives for this asset — what a pentest agent should test (e.g., 'Test for IDOR in /api/orders/{id}')",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async (asset) => {
      // -- Dedup check (when a shared registry is available) ----------------
      if (ctx.attackSurfaceRegistry) {
        const check = await ctx.attackSurfaceRegistry.register(asset);
        if (check.duplicate) {
          const matchName = check.matchedAsset?.assetName ?? "unknown";
          return {
            success: false,
            duplicate: true,
            matchType: check.matchType,
            matchedAsset: matchName,
            message: `Duplicate asset (${check.matchType}): already documented as "${matchName}". Skipping.`,
          };
        }
      }

      // Ensure assets directory exists
      if (!existsSync(assetsPath)) {
        mkdirSync(assetsPath, { recursive: true });
      }

      const sanitizedName = asset.assetName
        .toLowerCase()
        .replace(/[^a-z0-9-_.]/g, "_");
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = `asset_${sanitizedName}_${timestamp}.json`;
      const filepath = join(assetsPath, filename);

      const riskScore = computeBlackboxRiskScore(
        asset.riskLevel,
        asset.assetType,
        asset.details,
        asset.notes,
      );

      const assetRecord: DocumentedAssetRecord = {
        ...asset,
        discoveredAt: new Date().toISOString(),
        sessionId: ctx.session.id,
        target: ctx.session.targets[0],
        riskScore,
      };

      try {
        writeFileSync(filepath, JSON.stringify(assetRecord, null, 2));
      } catch (writeError: unknown) {
        if (ctx.attackSurfaceRegistry) {
          await ctx.attackSurfaceRegistry.unregister(asset);
        }
        throw writeError;
      }

      return {
        success: true,
        assetName: asset.assetName,
        assetType: asset.assetType,
        riskLevel: asset.riskLevel,
        filepath,
        message: `Asset '${asset.assetName}' documented successfully in assets directory`,
      };
    },
  });
}
