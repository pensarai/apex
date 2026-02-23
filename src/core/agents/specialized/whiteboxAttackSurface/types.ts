import { z } from "zod";

// ---------------------------------------------------------------------------
// Endpoint & App schemas
// ---------------------------------------------------------------------------

export const EndpointSchema = z.object({
  method: z
    .string()
    .describe(
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
  pentestObjectives: z
    .array(z.string())
    .describe(
      "Specific pentest objectives for this endpoint (e.g. 'Test for IDOR by enumerating user IDs', 'Test for SQL injection in search parameter')",
    ),
});

export type Endpoint = z.infer<typeof EndpointSchema>;

export const AppSchema = z.object({
  name: z.string().describe("Application or service name"),
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
