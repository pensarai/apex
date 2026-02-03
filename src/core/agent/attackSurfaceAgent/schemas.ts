import { z } from "zod";

/**
 * Shared schemas for attack surface agent tools.
 * These schemas are exported for use by external consumers (e.g., Console integration)
 * to validate and type persistence callbacks without duplicating schema definitions.
 */

/**
 * Schema for asset details object
 */
export const AssetDetailsSchema = z.object({
  url: z.string().optional().describe("URL if applicable"),
  ip: z.string().optional().describe("IP address if known"),
  ports: z.array(z.number()).optional().describe("Open ports"),
  services: z
    .array(z.string())
    .optional()
    .describe("Running services (e.g., 'nginx 1.18', 'SSH 8.2')"),
  technology: z
    .array(z.string())
    .optional()
    .describe("Technology stack (e.g., 'Node.js', 'Express', 'MongoDB')"),
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
    .describe("Status (active, inactive, redirect, error) or HTTP status code"),
});

/**
 * Asset types enum
 */
export const AssetTypeEnum = z.enum([
  "domain",
  "subdomain",
  "web_application",
  "api",
  "admin_panel",
  "infrastructure_service",
  "cloud_resource",
  "development_asset",
  "endpoint",
]);

/**
 * Risk level enum
 */
export const RiskLevelEnum = z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

/**
 * Schema for document_asset tool input
 */
export const DocumentAssetSchema = z.object({
  assetName: z
    .string()
    .describe(
      "Unique name for the asset (e.g., 'example.com', 'api.example.com', 'admin-panel')"
    ),
  assetType: AssetTypeEnum.describe("Type of asset discovered"),
  description: z
    .string()
    .describe(
      "Detailed description of the asset including what it is and why it's relevant"
    ),
  details: z
    .preprocess((val) => {
      if (typeof val === "string") {
        try {
          return JSON.parse(val);
        } catch {
          return {};
        }
      }
      return val;
    }, AssetDetailsSchema)
    .describe("Additional details about the asset"),
  riskLevel: z
    .preprocess((val) => {
      if (typeof val === "string") {
        const upper = val.toUpperCase();
        if (upper.includes("CRITICAL")) return "CRITICAL";
        if (upper.includes("HIGH")) return "HIGH";
        if (upper.includes("MEDIUM")) return "MEDIUM";
        if (upper.includes("LOW")) return "LOW";
      }
      return val;
    }, RiskLevelEnum)
    .describe("Risk level: LOW-CRITICAL (exposed/sensitive)"),
  notes: z
    .string()
    .optional()
    .describe("Additional notes or observations about the asset"),
});

/**
 * Schema for pentest target in attack surface report
 */
export const PentestTargetSchema = z.object({
  target: z.string().describe("Target URL, IP, or domain"),
  objective: z.string().describe("Pentest objective for this target"),
  rationale: z.string().describe("Why this target needs deep testing"),
  authenticationInfo: z
    .object({
      method: z.string(),
      details: z.string(),
      credentials: z.string().optional(),
      cookies: z.string().optional(),
      headers: z.string().optional(),
    })
    .optional(),
});

/**
 * Schema for attack surface summary
 */
export const AttackSurfaceSummarySchema = z.object({
  totalAssets: z.number(),
  totalDomains: z.number(),
  analysisComplete: z.boolean(),
});

/**
 * Schema for create_attack_surface_report tool input
 */
export const AttackSurfaceReportSchema = z.object({
  summary: AttackSurfaceSummarySchema.describe("Summary statistics"),
  discoveredAssets: z
    .array(z.string())
    .describe(
      "List of discovered assets with descriptions. Format: 'example.com - Web server (nginx) - Ports 80,443'"
    ),
  targets: z
    .array(PentestTargetSchema)
    .describe("ALL targets for deep penetration testing"),
  keyFindings: z.preprocess(
    (val) => (Array.isArray(val) ? val : [val]),
    z
      .array(z.string())
      .describe(
        "Key findings from reconnaissance. Format: '[SEVERITY] Finding description'"
      )
  ),
});

/**
 * Schema for documented asset record (includes metadata added during documentation)
 */
export const DocumentedAssetRecordSchema = DocumentAssetSchema.extend({
  discoveredAt: z.string().describe("ISO timestamp when asset was discovered"),
  sessionId: z.string().describe("Session ID where asset was discovered"),
  target: z.string().describe("Target being analyzed when asset was found"),
});

// Type exports
export type AssetDetails = z.infer<typeof AssetDetailsSchema>;
export type AssetType = z.infer<typeof AssetTypeEnum>;
export type RiskLevel = z.infer<typeof RiskLevelEnum>;
export type DocumentAssetInput = z.infer<typeof DocumentAssetSchema>;
export type DocumentedAssetRecord = z.infer<typeof DocumentedAssetRecordSchema>;
export type PentestTarget = z.infer<typeof PentestTargetSchema>;
export type AttackSurfaceSummary = z.infer<typeof AttackSurfaceSummarySchema>;
export type AttackSurfaceReport = z.infer<typeof AttackSurfaceReportSchema>;
