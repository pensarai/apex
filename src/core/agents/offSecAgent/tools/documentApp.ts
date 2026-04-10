import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import type { ToolContext } from "./types";

function sanitizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
}

/**
 * Factory for the `document_app` tool.
 *
 * Documents a discovered application during attack surface analysis —
 * writes a JSON file to the session's apps directory. This tool is
 * specifically for application-level entities (web apps, APIs, admin panels,
 * services) and is designed for incremental creation via the MessageManager
 * in Console.
 */
export function documentApp(ctx: ToolContext) {
  const baseAppsPath = join(ctx.session.rootPath, "apps");

  return tool({
    description: `Document a discovered application during attack surface analysis.

Applications are top-level entities discovered during reconnaissance — web applications, APIs, admin panels, or services. Each application groups related endpoints.

Use this tool to document:
- Web applications (the main target app, internal tools, dashboards)
- API services (REST APIs, GraphQL services)
- Admin panels or management interfaces
- Discovered subdomains hosting distinct applications
- Cloud resources (S3 buckets, cloud storage, CDN origins, etc.)

Do NOT use this for individual endpoints — use \`document_endpoint\` instead.
Do NOT use this for external/third-party services (CDNs, auth providers, SaaS) unless they are cloud resources owned by the target.

Each application creates a JSON file in the apps directory for tracking and analysis.`,
    inputSchema: z.object({
      appName: z
        .string()
        .describe(
          "Unique name for the application (e.g., 'Main Web App', 'Admin API', 'api.example.com')",
        ),
      appType: z
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
        .describe("Type of application discovered"),
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
      technology: z
        .array(z.string())
        .optional()
        .describe("Technology stack (e.g., ['Node.js', 'Express', 'MongoDB'])"),
      authentication: z
        .string()
        .optional()
        .describe(
          "Authentication type if known (e.g., 'OAuth2', 'JWT', 'session-based')",
        ),
      notes: z
        .string()
        .optional()
        .describe("Additional notes or observations about the application"),
      domain: z
        .string()
        .optional()
        .describe(
          "Base URL / domain this application is associated with (e.g., 'https://example.com'). " +
            "Used to map applications to monitored domains. " +
            "For cloud resources set this to the canonical resource URL " +
            "(e.g., 'https://bucket-name.s3.amazonaws.com').",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async (input) => {
      if (!existsSync(baseAppsPath)) {
        mkdirSync(baseAppsPath, { recursive: true });
      }

      const sanitizedName = sanitizeName(input.appName);
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = `app_${sanitizedName}_${timestamp}.json`;
      const filepath = join(baseAppsPath, filename);

      const appRecord = {
        ...input,
        discoveredAt: new Date().toISOString(),
        sessionId: ctx.session.id,
        target: ctx.session.targets[0],
      };

      writeFileSync(filepath, JSON.stringify(appRecord, null, 2));

      return {
        success: true,
        appName: input.appName,
        appType: input.appType,
        filepath,
        message: `Application '${input.appName}' documented successfully`,
      };
    },
  });
}
