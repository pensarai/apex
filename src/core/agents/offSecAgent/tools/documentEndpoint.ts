import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import type { ToolContext } from "./types";
import { computeBlackboxRiskScore } from "../../specialized/attackSurface/blackboxRiskScoring";
import { generateThreatModelForEndpoint } from "./threatModelGenerator";
import {
  VectorContextSchema,
  type VectorContext,
  PentestObjectiveSchema,
  PentestObjectivesField,
  type PentestObjective,
} from "../../specialized/attackSurface/schemas";
import { generateObjectResponse, type AIModel } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";

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
    description: `Document a discovered endpoint or attack surface component during analysis.

Components include API routes, web pages, infrastructure resources, and custom attack vectors. Each belongs to an application (specified by appName).

Use this tool to document:
- API endpoints (type: "api-endpoint") — REST routes, GraphQL, webhooks, auth endpoints
- Web pages and views (type: "web-endpoint") — dashboards, admin panels, SPAs
- Infrastructure (type: "infrastructure") — databases, S3 buckets, message queues, CDN distributions
- Custom vectors (type: "custom") — third-party integrations (Stripe, Slack, etc.), OAuth flows, cron jobs, file processors, SDK-based interactions

**API endpoint consolidation:** Do NOT create separate entries for each HTTP method on the same path. Document each unique path ONCE and list all supported methods in \`method\` (e.g., \`["GET", "POST", "DELETE"]\`). Use \`"PAGE"\` for web pages/views.

**Custom/infrastructure endpoints:** For non-HTTP components, use \`routePath\` as a namespace:component identifier (e.g., "stripe:webhook-handler", "sqs:order-consumer"). Provide \`vectorContext\` with interaction details.

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
        .enum(["api-endpoint", "web-endpoint", "infrastructure", "custom"])
        .describe(
          "Type of endpoint: 'api-endpoint' for HTTP APIs, 'web-endpoint' for pages/views, " +
            "'infrastructure' for databases/queues/storage/cloud resources, " +
            "'custom' for integrations/webhooks/SDK components/non-standard surfaces",
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
          "The HTTP route or access path served by this endpoint (e.g., '/api/users', '/dashboard'). " +
            "This is the URL path a client requests — NOT a source-file path. " +
            "Use the separate 'file' field for the source-code location. " +
            "For cloud resource endpoints (endpointType 'asset'), use the specific access pattern " +
            "or path — NOT the base domain URL, which is already stored on the parent application. " +
            "Examples: '/{objectKey}?X-Amz-Signature=...', '/index.html', 'arn:aws:s3:::bucket-name'.",
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
      pentestObjectives: PentestObjectivesField.describe(
        "Pentest objectives — each can be a string or { objective, instructions }",
      ),
      vectorContext: VectorContextSchema.optional().describe(
        "Structured metadata for custom/infrastructure endpoints. Required for type 'custom'. " +
          "For custom endpoints, use routePath as namespace:component (e.g., 'stripe:webhook-handler').",
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

      if (
        input.routePath &&
        (input.routePath.startsWith("https://") ||
          input.routePath.startsWith("http://"))
      ) {
        return {
          success: false,
          error: "routePath_is_url",
          message:
            `routePath "${input.routePath}" is a full URL. The domain is already stored on the parent application. ` +
            `Use a path or access pattern instead (e.g. "/api/users", "/{objectKey}?X-Amz-Signature={sig}", "arn:aws:s3:::bucket-name").`,
        };
      }

      // Dedicated objective generation — refine seed objectives with a focused LLM call
      let enrichedObjectives = input.pentestObjectives;
      if (ctx.model && ctx.authConfig) {
        try {
          enrichedObjectives = await generateEnrichedObjectives({
            model: ctx.model,
            authConfig: ctx.authConfig,
            endpoint: {
              name: input.endpointName,
              type: input.endpointType,
              description: input.description,
              routePath: input.routePath,
              method: input.method,
              handler: input.handler,
              file: input.file,
              authRequired: input.authRequired,
              vectorContext: input.vectorContext,
            },
            seedObjectives: input.pentestObjectives,
            abortSignal: ctx.abortSignal,
          });
        } catch {
          // Fall back to seed objectives on failure — non-critical
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

      const threatModel = await generateThreatModelForEndpoint(ctx, {
        appName: input.appName,
        endpointName: input.endpointName,
        routePath: input.routePath,
        method: input.method,
        file: input.file,
        line: input.line,
        handler: input.handler,
        authRequired: input.authRequired,
        description: input.description,
        pentestObjectives: input.pentestObjectives,
      });

      const endpointRecord = {
        ...input,
        pentestObjectives: enrichedObjectives,
        discoveredAt: new Date().toISOString(),
        sessionId: ctx.session.id,
        target: ctx.session.targets[0],
        riskScore,
        ...(threatModel ? { threatModel } : {}),
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

// ---------------------------------------------------------------------------
// Objective generation
// ---------------------------------------------------------------------------

const OBJECTIVE_GENERATION_SYSTEM_PROMPT = `You are a security testing objective generator. Given an endpoint or attack surface component, produce detailed, procedural testing objectives that a penetration tester can follow step-by-step.

Rules:
- Each objective must have an "objective" field (the testing goal) and an "instructions" field (setup steps, prerequisites, and how-to guidance)
- The "instructions" field should tell the agent: what to set up first, how to authenticate, what tools/protocols to use, and what constitutes a finding
- For custom vectors (webhooks, integrations, SDK components): instructions should describe the interaction protocol, authentication mechanism, and expected payload formats
- For infrastructure (databases, queues, storage): instructions should describe how to connect, what access patterns to test, and what misconfigurations to look for
- For standard HTTP endpoints: instructions should describe specific payloads, parameter manipulation, and verification steps
- Build on the seed objectives provided — refine vague ones and add missing coverage
- Return 3-8 objectives total (don't overload)`;

interface ObjectiveGenerationInput {
  model: AIModel;
  authConfig: AIAuthConfig;
  endpoint: {
    name: string;
    type: string;
    description: string;
    routePath?: string;
    method?: string | string[];
    handler?: string;
    file?: string;
    authRequired?: boolean;
    vectorContext?: VectorContext;
  };
  seedObjectives: PentestObjective[];
  abortSignal?: AbortSignal;
}

async function generateEnrichedObjectives(
  input: ObjectiveGenerationInput,
): Promise<PentestObjective[]> {
  const { model, authConfig, endpoint, seedObjectives, abortSignal } = input;

  const endpointContext = [
    `Name: ${endpoint.name}`,
    `Type: ${endpoint.type}`,
    `Description: ${endpoint.description}`,
    endpoint.routePath ? `Route/Identifier: ${endpoint.routePath}` : null,
    endpoint.method
      ? `Method: ${Array.isArray(endpoint.method) ? endpoint.method.join(", ") : endpoint.method}`
      : null,
    endpoint.handler ? `Handler: ${endpoint.handler}` : null,
    endpoint.file ? `Source file: ${endpoint.file}` : null,
    endpoint.authRequired != null
      ? `Auth required: ${endpoint.authRequired}`
      : null,
  ]
    .filter(Boolean)
    .join("\n");

  const vectorSection = endpoint.vectorContext
    ? `\nVector Context:\n- Component type: ${endpoint.vectorContext.componentType}\n- Interaction protocol: ${endpoint.vectorContext.interactionProtocol}\n- Prerequisites: ${endpoint.vectorContext.prerequisites.join(", ") || "None"}\n- Auth instructions: ${endpoint.vectorContext.authInstructions}\n- Additional context: ${endpoint.vectorContext.additionalContext}`
    : "";

  const seedList = seedObjectives
    .map((o, i) => {
      let text = `${i + 1}. ${o.objective}`;
      if (o.instructions) text += `\n   Instructions: ${o.instructions}`;
      return text;
    })
    .join("\n");

  const prompt = `Generate detailed, procedural pentest objectives for this endpoint.

## Endpoint
${endpointContext}${vectorSection}

## Seed Objectives (from recon agent)
${seedList}

Refine and expand these into structured objectives. Each objective must have an "objective" field (the goal) and an "instructions" field (step-by-step setup and testing guidance).`;

  const result = await generateObjectResponse({
    model,
    schema: z.object({
      objectives: z
        .array(PentestObjectiveSchema)
        .describe("Detailed objectives with setup instructions"),
    }),
    prompt,
    system: OBJECTIVE_GENERATION_SYSTEM_PROMPT,
    authConfig,
    abortSignal,
    maxTokens: 4096,
    temperature: 0.3,
  });

  if (
    result &&
    Array.isArray(result.objectives) &&
    result.objectives.length > 0
  ) {
    return result.objectives;
  }

  return seedObjectives;
}
