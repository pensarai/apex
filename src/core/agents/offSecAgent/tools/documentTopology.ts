import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

/**
 * `document_boundary`, `document_service`, and `document_flow` record the
 * system topology behind an origin: where things run, what each application
 * depends on, and how traffic moves between them. Together with
 * `document_app` they describe boundaries → applications → services.
 *
 * Every record carries evidence, because most of a system's interior is not
 * reachable from the origin: datastores behind a VPC are known from source or
 * a cloud API, not from a live probe, and the consumer renders the difference.
 *
 * Records are session artifacts under `topology/`. A later call for the same
 * name supersedes an earlier one.
 */

export const EVIDENCE_SOURCES = [
  "observed",
  "source",
  "cloud",
  "inferred",
] as const;

const evidenceSchema = z
  .array(
    z.object({
      source: z
        .enum(EVIDENCE_SOURCES)
        .describe(
          "observed = a live probe returned it; source = read in a connected repository (IaC, config, code); cloud = a cloud-provider API returned it; inferred = deduced, not confirmed",
        ),
      detail: z.string().describe("What the evidence shows, in one sentence."),
      ref: z
        .string()
        .optional()
        .describe("File path, URL, or API call the evidence came from."),
    }),
  )
  .min(1)
  .describe(
    "At least one piece of evidence. Never claim 'cloud' unless a cloud API returned it.",
  );

export const BOUNDARY_KINDS = [
  "edge-network",
  "cloud-account",
  "region",
  "vpc",
  "subnet",
  "third-party",
] as const;

export const SERVICE_KINDS = [
  "entrypoint",
  "compute",
  "database",
  "cache",
  "queue",
  "object-store",
  "message-broker",
  "proxy",
  "identity-provider",
  "llm-provider",
  "saas",
  "secret-store",
] as const;

const CONTROL_KINDS = [
  "waf",
  "ip-allowlist",
  "geo-block",
  "security-group",
  "origin-secret",
  "authentication",
  "network-isolation",
  "logging",
] as const;

type TopologyKind = "boundary" | "service" | "flow";

function sanitize(name: string): string {
  const cleaned = name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
  return cleaned && cleaned !== "." && cleaned !== ".." ? cleaned : "unnamed";
}

function topologyDir(ctx: ToolContext): string {
  return join(ctx.session.rootPath, "topology");
}

function writeRecord(
  ctx: ToolContext,
  kind: TopologyKind,
  key: string,
  record: Record<string, unknown>,
): string {
  const dir = topologyDir(ctx);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filepath = join(dir, `${kind}_${sanitize(key)}_${timestamp}.json`);
  writeFileSync(
    filepath,
    JSON.stringify(
      {
        ...record,
        recordedAt: new Date().toISOString(),
        sessionId: ctx.session.id,
      },
      null,
      2,
    ),
  );
  return filepath;
}

/** Lower-cased names already documented for a kind, so references can be checked. */
function documentedNames(
  ctx: ToolContext,
  kind: "boundary" | "service" | "app",
): Set<string> {
  const dir =
    kind === "app" ? join(ctx.session.rootPath, "apps") : topologyDir(ctx);
  const prefix = kind === "app" ? "app_" : `${kind}_`;
  const field = kind === "app" ? "appName" : "name";
  const names = new Set<string>();
  if (!existsSync(dir)) return names;
  for (const file of readdirSync(dir)) {
    if (!file.startsWith(prefix) || !file.endsWith(".json")) continue;
    const record = JSON.parse(readFileSync(join(dir, file), "utf8")) as Record<
      string,
      unknown
    >;
    const name = record[field];
    if (typeof name === "string") names.add(name.toLowerCase());
  }
  return names;
}

/** Error result for `document_app` when its `boundary` names nothing documented; null when valid. */
export function checkBoundaryReference(ctx: ToolContext, boundary: string) {
  const boundaries = documentedNames(ctx, "boundary");
  return boundaries.has(boundary.toLowerCase())
    ? null
    : unknownReference(
        "boundary",
        boundary,
        boundaries,
        "Document it with document_boundary first.",
      );
}

function unknownReference(
  what: string,
  name: string,
  known: Set<string>,
  fix: string,
) {
  return {
    success: false,
    error: `unknown_${what}`,
    message: `No ${what} named "${name}" has been documented. ${fix}${
      known.size ? ` Documented: ${[...known].join(", ")}.` : ""
    }`,
  };
}

const toolCallDescription = z
  .string()
  .describe(
    "A concise, human-readable description of what this tool call is doing",
  );

export function documentBoundary(ctx: ToolContext) {
  return tool({
    description: `Document a boundary that contains applications and services: an edge network (CDN, Cloudflare), a cloud account, a region, a VPC, a subnet tier, or the set of third-party services the system relies on.

Record the rules that govern traffic into the boundary as controls (WAF rules, IP allowlists, security groups, origin secrets, network isolation). Nest boundaries with \`parent\` — e.g. subnet → VPC → region → cloud account. Document a parent before its children.

Call again with the same name to update a boundary.`,
    inputSchema: z.object({
      name: z
        .string()
        .describe(
          "Unique boundary name, e.g. 'AWS production account', 'Console VPC', 'Private subnets'.",
        ),
      kind: z.enum(BOUNDARY_KINDS),
      provider: z
        .string()
        .optional()
        .describe("e.g. 'aws', 'cloudflare', 'gcp'."),
      parent: z
        .string()
        .optional()
        .describe(
          "Name of an already-documented boundary this one sits inside.",
        ),
      description: z.string().optional(),
      controls: z
        .array(
          z.object({
            kind: z.enum(CONTROL_KINDS),
            summary: z
              .string()
              .describe("What the rule allows or blocks, concretely."),
            evidence: evidenceSchema,
          }),
        )
        .optional()
        .describe("Rules governing traffic into or within this boundary."),
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      if (input.parent) {
        const boundaries = documentedNames(ctx, "boundary");
        if (!boundaries.has(input.parent.toLowerCase()))
          return unknownReference(
            "boundary",
            input.parent,
            boundaries,
            "Document the parent boundary first.",
          );
      }
      const { toolCallDescription: _, ...record } = input;
      const filepath = writeRecord(ctx, "boundary", input.name, record);
      return {
        success: true,
        name: input.name,
        kind: input.kind,
        parent: input.parent,
        filepath,
        message: `Boundary '${input.name}' documented`,
      };
    },
  });
}

export function documentService(ctx: ToolContext) {
  return tool({
    description: `Document a service that applications depend on or are reached through: entry points (CDN distributions, load balancers, API gateways, function URLs, MQTT endpoints), datastores (databases, caches, object stores), queues and brokers, shared compute (workers), identity providers, LLM providers, and SaaS.

Document services even when they are not reachable from the origin — a database in a private subnet is part of the surface. Its evidence will then be 'source' (IaC, config, code) or 'inferred', not 'observed'.

\`applications\` lists the documented applications that use this service; that is what an application drill-down shows. Call again with the same name to update a service.`,
    inputSchema: z.object({
      name: z
        .string()
        .describe(
          "Unique service name, e.g. 'Aurora PostgreSQL', 'api.example.com', 'SQS queues'.",
        ),
      kind: z.enum(SERVICE_KINDS),
      boundary: z
        .string()
        .describe(
          "Name of the already-documented boundary this service runs in.",
        ),
      tech: z
        .string()
        .optional()
        .describe("e.g. 'Aurora PostgreSQL 16 behind RDS Proxy'."),
      exposure: z
        .enum(["public", "private", "unknown"])
        .describe(
          "public = reachable from the internet; private = only from inside its boundary.",
        ),
      endpoints: z
        .array(z.string())
        .optional()
        .describe("Hostnames or URLs it answers on."),
      applications: z
        .array(z.string())
        .describe(
          "Names of documented applications that use this service (from document_app).",
        ),
      description: z.string().optional(),
      members: z
        .array(z.string())
        .optional()
        .describe("For a collapsed group (e.g. 12 queues), the member names."),
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const boundaries = documentedNames(ctx, "boundary");
      if (!boundaries.has(input.boundary.toLowerCase()))
        return unknownReference(
          "boundary",
          input.boundary,
          boundaries,
          "Document it with document_boundary first.",
        );
      const apps = documentedNames(ctx, "app");
      const missing = input.applications.find(
        (name) => !apps.has(name.toLowerCase()),
      );
      if (missing)
        return unknownReference(
          "application",
          missing,
          apps,
          "Document it with document_app first, or use its exact appName.",
        );
      const { toolCallDescription: _, ...record } = input;
      const filepath = writeRecord(ctx, "service", input.name, record);
      return {
        success: true,
        name: input.name,
        kind: input.kind,
        boundary: input.boundary,
        filepath,
        message: `Service '${input.name}' documented`,
      };
    },
  });
}

export function documentFlow(ctx: ToolContext) {
  return tool({
    description: `Document how traffic or data moves between two documented nodes (applications or services): e.g. CDN → web app, web app → database, worker → queue, sandbox → egress proxy.

\`from\` and \`to\` are the exact names used in document_app or document_service. Call again with the same from/to/label to update a flow.`,
    inputSchema: z.object({
      from: z
        .string()
        .describe(
          "Name of the documented application or service traffic originates from.",
        ),
      to: z
        .string()
        .describe("Name of the documented application or service it reaches."),
      label: z
        .string()
        .describe(
          "Short protocol or purpose, e.g. 'HTTPS', 'RDS Proxy', 'enqueue jobs'.",
        ),
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const nodes = new Set([
        ...documentedNames(ctx, "app"),
        ...documentedNames(ctx, "service"),
      ]);
      for (const end of [input.from, input.to])
        if (!nodes.has(end.toLowerCase()))
          return unknownReference(
            "node",
            end,
            nodes,
            "Document it with document_app or document_service first.",
          );
      const { toolCallDescription: _, ...record } = input;
      const filepath = writeRecord(
        ctx,
        "flow",
        `${input.from}__${input.to}__${input.label}`,
        record,
      );
      return {
        success: true,
        from: input.from,
        to: input.to,
        filepath,
        message: `Flow '${input.from}' → '${input.to}' documented`,
      };
    },
  });
}
