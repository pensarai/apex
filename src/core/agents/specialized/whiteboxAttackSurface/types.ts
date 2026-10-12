import { z } from "zod";
import {
  EndpointTransportEnum,
  GrpcEndpointMetadataSchema,
} from "../attackSurface/grpcSchema";

// ---------------------------------------------------------------------------
// Risk score schemas
// ---------------------------------------------------------------------------

export const RiskScoreBreakdownSchema = z.object({
  exposure: z
    .number()
    .min(0)
    .max(3)
    .describe(
      "Exposure Level (0-3): 3=Public no auth, 2=Standard user login, 1=Privileged/admin access, 0=Private/internal-only",
    ),
  dataSensitivity: z
    .number()
    .min(0)
    .max(3)
    .describe(
      "Data Sensitivity (0-3): 3=PII/PHI/financial/passwords/tokens, 2=Business operations/configs, 1=Low-value user data, 0=No meaningful data",
    ),
  functionCriticality: z
    .number()
    .min(0)
    .max(2)
    .describe(
      "Function Criticality (0-2): 2=Auth flows/payments/state-changing mutations, 1=Core product functionality, 0=Non-critical content",
    ),
  securityIndicators: z
    .number()
    .min(0)
    .max(2)
    .describe(
      "Security Indicators (0-2): 2=Critical vuln patterns (SQLi, command injection, hardcoded secrets), 1=Moderate concerns (missing validation, weak error handling), 0=No obvious issues",
    ),
});

export const RiskScoreSchema = z.object({
  score: z.number().min(0).max(10).describe("Total risk score (0-10)"),
  explanation: z.string().describe("Justification for the risk score"),
  breakdown: RiskScoreBreakdownSchema,
});

export type RiskScore = z.infer<typeof RiskScoreSchema>;
export type RiskScoreBreakdown = z.infer<typeof RiskScoreBreakdownSchema>;

// ---------------------------------------------------------------------------
// Endpoint & App schemas
// ---------------------------------------------------------------------------

// The model routinely emits `method` as an array for multi-method endpoints
// (e.g. ["GET","POST"]). Accept both shapes and normalize to a single string —
// matching how `assetRecordToEndpoint` in the whitebox workflow already joins
// array methods — so downstream consumers keep a plain string.
const MethodSchema = z
  .union([z.string(), z.array(z.string())])
  .transform((m) => (Array.isArray(m) ? m.join(", ") : m));

// Array-of-strings fields where the model sometimes emits a single bare string.
// Wrap a lone string into a one-element array instead of rejecting the payload.
const StringListSchema = z
  .union([z.string(), z.array(z.string())])
  .transform((v) => (Array.isArray(v) ? v : [v]));

export const EndpointSchema = z.object({
  method: MethodSchema.describe(
    "HTTP method (GET, POST, PUT, DELETE, etc.) or 'PAGE' for web pages",
  ),
  path: z.string().describe("Route path (e.g. /api/users/:id, /dashboard)"),
  handler: z
    .string()
    .optional()
    .describe("Handler function or component name, if identifiable"),
  file: z.string().describe("File where this endpoint is defined"),
  line: z.number().optional().describe("Line number in the file"),
  authRequired: z
    .boolean()
    .optional()
    .describe("Whether this endpoint appears to require authentication"),
  description: z
    .string()
    .optional()
    .describe("Brief description of what this endpoint does"),
  pentestObjectives: StringListSchema.default([]).describe(
    "Pentest objectives for this endpoint, derived from the threat model when available " +
      "(e.g. 'Test for IDOR by enumerating user IDs', 'Test for SQL injection in search parameter')",
  ),
  riskScore: RiskScoreSchema.optional().describe(
    "AI-calculated risk score for prioritizing pentest efforts",
  ),
  threatModel: z
    .string()
    .optional()
    .describe(
      "Endpoint-specific threat model describing attack vectors, data sensitivity, and testing priorities",
    ),
  transport: EndpointTransportEnum.optional().describe(
    "Wire transport; 'grpc'/'grpc_web'/'connect' for gRPC methods, else http",
  ),
  grpc: GrpcEndpointMetadataSchema.optional().describe(
    "gRPC service/method/streaming metadata when transport is a gRPC variant",
  ),
});

export type Endpoint = z.infer<typeof EndpointSchema>;

export const AppSchema = z.object({
  name: z.string().describe("Application or service name"),
  type: z
    .enum([
      "web_application",
      "api",
      "full_stack",
      "domain",
      "subdomain",
      "database",
      "cloud_resource",
      "storage",
    ])
    .default("web_application")
    .describe(
      "Type of application (web_application, api, full_stack, database, cloud_resource, storage, etc.)",
    ),
  framework: z
    .string()
    .describe(
      "Framework in use (e.g. Express, Next.js, Django, FastAPI, Rails)",
    ),
  description: z.string().describe("Brief description of what this app does"),
  location: z
    .string()
    .describe("Path to the app root relative to the repository root"),
  pages: z
    .array(EndpointSchema)
    .describe("Web pages / views defined in this app"),
  apiEndpoints: z
    .array(EndpointSchema)
    .describe("API endpoints defined in this app"),
});

export type App = z.infer<typeof AppSchema>;

// ---------------------------------------------------------------------------
// Workflow intermediate schemas
// ---------------------------------------------------------------------------

export const AppInfoSchema = z.object({
  name: z.string().describe("Application or service name"),
  framework: z
    .string()
    .describe(
      "Framework or cloud service (e.g. Express, Next.js, Django, FastAPI, Rails, AWS S3, CloudFront)",
    ),
  description: z.string().describe("Brief description of what this app does"),
  location: z
    .string()
    .describe(
      "Path to the app root relative to the repository root, or resource identifier for cloud resources",
    ),
  type: z
    .enum([
      "web_application",
      "api",
      "full_stack",
      "domain",
      "subdomain",
      "database",
      "cloud_resource",
      "storage",
    ])
    .default("web_application")
    .describe(
      "Application type — web_application for frontend apps, api for backend services, " +
        "full_stack for frameworks like Next.js/Remix that serve both, " +
        "database for databases, cloud_resource for owned cloud infra, storage for S3/GCS/blob storage",
    ),
});

export type AppInfo = z.infer<typeof AppInfoSchema>;

export const AppsDiscoveryResultSchema = z.object({
  repoType: z.string().describe("e.g. monorepo, single-app, multi-package"),
  packageManager: z
    .string()
    .describe("e.g. npm, yarn, pnpm, pip, cargo, go modules"),
  apps: z
    .array(AppInfoSchema)
    .describe("All applications/services discovered in the repository"),
});

export type AppsDiscoveryResult = z.infer<typeof AppsDiscoveryResultSchema>;

export const DiscoverySummarySchema = z.object({
  endpointsDocumented: z
    .number()
    .describe("Number of endpoints documented via document_endpoint"),
  summary: z.string().describe("Brief summary of what was found"),
});

export type DiscoverySummary = z.infer<typeof DiscoverySummarySchema>;

// ---------------------------------------------------------------------------
// Top-level result schema
// ---------------------------------------------------------------------------

export const WhiteboxAttackSurfaceResultSchema = z.object({
  repoType: z
    .string()
    .describe(
      "Repository structure type (e.g. 'monorepo', 'single-app', 'multi-package')",
    ),
  packageManager: z
    .string()
    .describe(
      "Package manager detected (e.g. npm, yarn, pnpm, pip, cargo, go modules)",
    ),
  apps: z
    .array(AppSchema)
    .describe("All applications discovered in the repository"),
  summary: z.object({
    totalApps: z.number(),
    totalPages: z.number(),
    totalApiEndpoints: z.number(),
    totalPentestObjectives: z.number(),
  }),
});

export type WhiteboxAttackSurfaceResult = z.infer<
  typeof WhiteboxAttackSurfaceResultSchema
>;
