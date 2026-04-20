import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import type { ToolContext } from "./types";

function sanitizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
}

/**
 * Validates that a domain string is a well-formed URL with scheme + host.
 * Returns a normalized origin string or null if invalid.
 */
function validateDomainUrl(value: string): {
  valid: boolean;
  origin: string | null;
  error: string | null;
} {
  const trimmed = value.trim();

  if (!trimmed.includes("://")) {
    return {
      valid: false,
      origin: null,
      error:
        `Domain "${trimmed}" is missing a URL scheme. ` +
        `Use a full URL with scheme (e.g., "https://${trimmed}" instead of "${trimmed}").`,
    };
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return {
        valid: false,
        origin: null,
        error:
          `Domain "${trimmed}" has an unsupported scheme "${parsed.protocol}". ` +
          `Use "https://" or "http://".`,
      };
    }
    if (!parsed.hostname) {
      return {
        valid: false,
        origin: null,
        error: `Domain "${trimmed}" has no hostname.`,
      };
    }
    return { valid: true, origin: parsed.origin, error: null };
  } catch {
    return {
      valid: false,
      origin: null,
      error:
        `Domain "${trimmed}" is not a valid URL. ` +
        `Provide a full URL (e.g., "https://example.com", "https://bucket.s3.amazonaws.com").`,
    };
  }
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
          "Base URL / domain this application is associated with. Only provide this if you can deterministically derive it from evidence — source code, IaC, config, Known Domains list, or live discovery. " +
            "Substituting a known environment/stage name into an IaC template IS deterministic (e.g. IaC defines '${stage}-bucket' and environments include 'production' → 'https://production-bucket.s3.amazonaws.com' is valid). " +
            "Do NOT invent domains with no supporting evidence — if no domain can be derived, omit this field. " +
            "Must be a full URL with scheme when provided. " +
            "For web apps/APIs: the public URL (e.g., 'https://api.example.com'). " +
            "For S3 buckets: 'https://{ACTUAL-BUCKET-NAME}.s3.amazonaws.com' — you MUST include the real bucket name from IaC, NOT 'https://s3.amazonaws.com'. " +
            "For databases (RDS/Aurora): 'https://{cluster-endpoint}.rds.amazonaws.com'. " +
            "For Redis/ElastiCache: 'https://{cluster-id}.cache.amazonaws.com'. " +
            "For SQS queues: 'https://sqs.{region}.amazonaws.com/{account}/{queue-name}'. " +
            "For Lambda functions: use the API Gateway or Function URL that routes to them, NOT a generic API domain. " +
            "For CDN/CloudFront: 'https://{distribution-id}.cloudfront.net'. " +
            "CRITICAL: each resource must have its OWN unique domain derived from its infrastructure definition — never reuse the console or API domain for unrelated resources.",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async (input) => {
      if (input.domain) {
        const domainCheck = validateDomainUrl(input.domain);
        if (!domainCheck.valid) {
          return {
            success: false,
            error: "invalid_domain",
            message: domainCheck.error!,
          };
        }
        input = { ...input, domain: domainCheck.origin! };
      }

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
        domain: input.domain,
        filepath,
        message: `Application '${input.appName}' documented successfully`,
      };
    },
  });
}
