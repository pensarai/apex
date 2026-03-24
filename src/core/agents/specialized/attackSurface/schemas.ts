import { z } from "zod";
import {
  RiskScoreSchema,
  RiskScoreBreakdownSchema,
} from "../whiteboxAttackSurface/types";

export { RiskScoreSchema, RiskScoreBreakdownSchema };
export type {
  RiskScore,
  RiskScoreBreakdown,
} from "../whiteboxAttackSurface/types";

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
  method: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .describe(
      "HTTP method(s) supported by this endpoint (e.g., 'GET', 'POST', or ['GET', 'POST', 'DELETE']). " +
        "Use this for endpoint-type assets to list ALL methods the endpoint accepts. " +
        "Multiple methods on the same path should be documented as a single asset with all methods listed here. " +
        "Use 'PAGE' for web pages/views.",
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
  file: z
    .string()
    .optional()
    .describe("Source file where this asset is defined (whitebox analysis)"),
  line: z
    .number()
    .optional()
    .describe("Line number in the source file (whitebox analysis)"),
  handler: z
    .string()
    .optional()
    .describe("Handler function or component name (whitebox analysis)"),
  authRequired: z
    .boolean()
    .optional()
    .describe("Whether authentication appears to be required"),
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
  appName: z
    .string()
    .optional()
    .describe(
      "Application name for organizing assets into app-specific folders. " +
        "When provided, the asset is stored under assets/<appName>/ instead of the flat assets/ directory. " +
        "Used by whitebox analysis to group endpoints by the application they belong to.",
    ),
  assetName: z
    .string()
    .describe(
      "Unique name for the asset (e.g., 'example.com', 'api.example.com', 'admin-panel')",
    ),
  assetType: AssetTypeEnum.describe("Type of asset discovered"),
  description: z
    .string()
    .describe(
      "Detailed description of the asset including what it is and why it's relevant",
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
  pentestObjectives: z
    .array(z.string())
    .describe(
      "Specific pentest objectives for this asset (e.g., 'Test for IDOR in /api/orders/{id}')",
    ),
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
      "List of discovered assets with descriptions. Format: 'example.com - Web server (nginx) - Ports 80,443'",
    ),
  targets: z
    .array(PentestTargetSchema)
    .describe("ALL targets for deep penetration testing"),
  keyFindings: z.preprocess(
    (val) => (Array.isArray(val) ? val : [val]),
    z
      .array(z.string())
      .describe(
        "Key findings from reconnaissance. Format: '[SEVERITY] Finding description'",
      ),
  ),
});

/**
 * Schema for documented asset record (includes metadata added during documentation)
 */
export const DocumentedAssetRecordSchema = DocumentAssetSchema.extend({
  discoveredAt: z.string().describe("ISO timestamp when asset was discovered"),
  sessionId: z.string().describe("Session ID where asset was discovered"),
  target: z.string().describe("Target being analyzed when asset was found"),
  riskScore: RiskScoreSchema.optional().describe(
    "Computed risk score with breakdown (heuristic for blackbox, AI-scored for whitebox)",
  ),

  /** @deprecated Flattened from details.url for console backwards compatibility */
  url: z.string().optional(),
  /** @deprecated Flattened from details.authRequired for console backwards compatibility */
  authRequired: z.boolean().optional(),
  /** @deprecated Flattened from details.authentication for console backwards compatibility */
  authentication: z.string().optional(),
  /** @deprecated Use assetName instead */
  endpointName: z.string().optional(),
  /** @deprecated Use assetType instead */
  endpointType: z.enum(["api-endpoint", "web-endpoint", "asset"]).optional(),
});

// ---------------------------------------------------------------------------
// document_app / document_endpoint schemas
// ---------------------------------------------------------------------------

/**
 * Application types for document_app tool
 */
export const AppTypeEnum = z.enum([
  "web_application",
  "api",
  "admin_panel",
  "domain",
  "subdomain",
]);

/**
 * Endpoint types for document_endpoint tool
 */
export const EndpointTypeEnum = z.enum([
  "api-endpoint",
  "web-endpoint",
  "asset",
]);

/**
 * Schema for document_app tool input
 */
export const DocumentAppSchema = z.object({
  appName: z
    .string()
    .describe(
      "Unique name for the application (e.g., 'Main Web App', 'Admin API', 'api.example.com')",
    ),
  appType: AppTypeEnum.describe("Type of application discovered"),
  description: z
    .string()
    .describe(
      "Detailed description of the application including what it is and why it's relevant",
    ),
  framework: z
    .string()
    .optional()
    .describe(
      "Technology framework or stack (e.g., 'Next.js', 'Express + React', 'Django')",
    ),
  url: z
    .string()
    .optional()
    .describe("Base URL of the application"),
  technology: z
    .array(z.string())
    .optional()
    .describe("Technology stack (e.g., ['Node.js', 'Express', 'MongoDB'])"),
  authentication: z
    .string()
    .optional()
    .describe("Authentication type if known"),
  notes: z.string().optional().describe("Additional notes or observations"),
});

/**
 * Schema for document_app record (includes metadata added during documentation)
 */
export const DocumentedAppRecordSchema = DocumentAppSchema.extend({
  discoveredAt: z.string().describe("ISO timestamp when app was discovered"),
  sessionId: z.string().describe("Session ID where app was discovered"),
  target: z.string().describe("Target being analyzed when app was found"),
});

/**
 * Schema for document_endpoint tool input
 */
export const DocumentEndpointSchema = z.object({
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
  endpointType: EndpointTypeEnum.describe(
    "Type of endpoint: 'api-endpoint' for REST/GraphQL APIs, " +
      "'web-endpoint' for pages/views, 'asset' for other resources",
  ),
  description: z
    .string()
    .describe("Detailed description of the endpoint including what it does"),
  url: z
    .string()
    .optional()
    .describe("The route path (e.g., '/api/users', '/dashboard')"),
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
    .describe("Source file where this endpoint is defined (whitebox analysis)"),
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
    .describe("Additional notes or observations about the endpoint"),
  pentestObjectives: z
    .array(z.string())
    .describe(
      "Specific pentest objectives for this endpoint (e.g., 'Test for IDOR in /api/orders/{id}')",
    ),
});

/**
 * Schema for document_endpoint record (includes metadata added during documentation)
 */
export const DocumentedEndpointRecordSchema = DocumentEndpointSchema.extend({
  discoveredAt: z
    .string()
    .describe("ISO timestamp when endpoint was discovered"),
  sessionId: z.string().describe("Session ID where endpoint was discovered"),
  target: z
    .string()
    .describe("Target being analyzed when endpoint was found"),
  riskScore: RiskScoreSchema.optional().describe(
    "Computed risk score with breakdown",
  ),
});

// Type exports
export type AssetDetails = z.infer<typeof AssetDetailsSchema>;
export type AssetType = z.infer<typeof AssetTypeEnum>;
export type AppType = z.infer<typeof AppTypeEnum>;
export type EndpointType = z.infer<typeof EndpointTypeEnum>;
export type RiskLevel = z.infer<typeof RiskLevelEnum>;
export type DocumentAssetInput = z.infer<typeof DocumentAssetSchema>;
export type DocumentedAssetRecord = z.infer<typeof DocumentedAssetRecordSchema>;
export type DocumentAppInput = z.infer<typeof DocumentAppSchema>;
export type DocumentedAppRecord = z.infer<typeof DocumentedAppRecordSchema>;
export type DocumentEndpointInput = z.infer<typeof DocumentEndpointSchema>;
export type DocumentedEndpointRecord = z.infer<
  typeof DocumentedEndpointRecordSchema
>;
export type PentestTarget = z.infer<typeof PentestTargetSchema>;
export type AttackSurfaceSummary = z.infer<typeof AttackSurfaceSummarySchema>;
export type AttackSurfaceReport = z.infer<typeof AttackSurfaceReportSchema>;

// Backwards compatibility aliases (deprecated)
/** @deprecated Use AssetType instead */
export type EndpointType = AssetType;

/**
 * @deprecated Use DocumentedAssetRecord instead.
 * Legacy type with required endpointName/endpointType for console apex-adapter compatibility.
 */
export type DocumentedEndpointRecord = DocumentedAssetRecord & {
  endpointName: string;
  endpointType: "api-endpoint" | "web-endpoint" | "asset";
};
