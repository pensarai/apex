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
 * Risk level enum
 */
export const RiskLevelEnum = z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

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
  "cloud_resource",
  "storage",
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
  domain: z
    .string()
    .optional()
    .describe(
      "Domain URL this application is associated with (e.g., 'https://example.com'). " +
        "Used to map applications to monitored domains. Only set if a known domain was provided.",
    ),
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
export type AppType = z.infer<typeof AppTypeEnum>;
export type EndpointType = z.infer<typeof EndpointTypeEnum>;
export type RiskLevel = z.infer<typeof RiskLevelEnum>;
export type DocumentAppInput = z.infer<typeof DocumentAppSchema>;
export type DocumentedAppRecord = z.infer<typeof DocumentedAppRecordSchema>;
export type DocumentEndpointInput = z.infer<typeof DocumentEndpointSchema>;
export type DocumentedEndpointRecord = z.infer<
  typeof DocumentedEndpointRecordSchema
>;
export type PentestTarget = z.infer<typeof PentestTargetSchema>;
export type AttackSurfaceSummary = z.infer<typeof AttackSurfaceSummarySchema>;
export type AttackSurfaceReport = z.infer<typeof AttackSurfaceReportSchema>;

