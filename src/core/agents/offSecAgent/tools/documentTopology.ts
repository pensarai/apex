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
 * The topology tools record the system behind one or more origins:
 * boundaries contain components, flows connect components, controls apply to
 * boundaries and components, and attack vectors span components.
 *
 * A component's threat model is composed rather than written as prose: the
 * agent records what is at stake and what the component trusts, and the
 * consumer derives reachability, controls, and vectors from the graph.
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

export const COMPONENT_KINDS = [
  "application",
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

export const CONTROL_KINDS = [
  "waf",
  "ip-allowlist",
  "geo-block",
  "security-group",
  "network-isolation",
  "origin-secret",
  "authentication",
  "authorization",
  "tenant-isolation",
  "rate-limit",
  "encryption",
  "secret-management",
  "iam-policy",
  "input-validation",
  "logging",
] as const;

export const VECTOR_PATTERNS = [
  "control-bypass",
  "missing-control",
  "trust-abuse",
  "shared-resource",
  "exposure",
  "misconfiguration",
] as const;

type RecordKind = "boundary" | "component" | "flow" | "control" | "vector";

function sanitize(name: string): string {
  const cleaned = name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
  return cleaned && cleaned !== "." && cleaned !== ".." ? cleaned : "unnamed";
}

function topologyDir(ctx: ToolContext): string {
  return join(ctx.session.rootPath, "topology");
}

function writeRecord(
  ctx: ToolContext,
  kind: RecordKind,
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

/** Latest record per lower-cased name for a kind, so references can be checked. */
function documented(
  ctx: ToolContext,
  kind: "boundary" | "component" | "control",
): Map<string, Record<string, unknown>> {
  const dir = topologyDir(ctx);
  const byName = new Map<string, Record<string, unknown>>();
  if (!existsSync(dir)) return byName;
  for (const file of readdirSync(dir).sort()) {
    if (!file.startsWith(`${kind}_`) || !file.endsWith(".json")) continue;
    const record = JSON.parse(readFileSync(join(dir, file), "utf8")) as Record<
      string,
      unknown
    >;
    if (typeof record.name === "string")
      byName.set(record.name.toLowerCase(), record);
  }
  return byName;
}

function unknownReference(
  what: string,
  name: string,
  known: Iterable<string>,
  fix: string,
) {
  const names = [...known];
  return {
    success: false,
    error: `unknown_${what}`,
    message: `No ${what} named "${name}" has been documented. ${fix}${
      names.length ? ` Documented: ${names.join(", ")}.` : ""
    }`,
  };
}

/** First name in `names` that `known` lacks, or undefined. */
function firstMissing(
  names: readonly string[],
  known: { has(name: string): boolean },
) {
  return names.find((name) => !known.has(name.toLowerCase()));
}

const toolCallDescription = z
  .string()
  .describe(
    "A concise, human-readable description of what this tool call is doing",
  );

export function documentBoundary(ctx: ToolContext) {
  return tool({
    description: `Document a boundary that contains components: an edge network (CDN, Cloudflare), a cloud account, a region, a VPC, a subnet tier, or the set of third-party services the system relies on.

Record the rules that govern it with document_control. Nest boundaries with \`parent\` — e.g. subnet → VPC → region → cloud account. Document a parent before its children.

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
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      if (input.parent) {
        const boundaries = documented(ctx, "boundary");
        if (!boundaries.has(input.parent.toLowerCase()))
          return unknownReference(
            "boundary",
            input.parent,
            boundaries.keys(),
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

export function documentComponent(ctx: ToolContext) {
  return tool({
    description: `Document a component of the system: an application users or attackers reach, or anything applications are reached through or depend on — entry points (CDN distributions, load balancers, API gateways, function URLs, MQTT endpoints), databases, caches, queues, object stores, brokers, shared workers, identity providers, LLM providers, SaaS.

Document components even when they are not reachable from the origin — a database in a private subnet is part of the surface. Its evidence will then be 'source' (IaC, config, code) or 'inferred', not 'observed'.

Every component gets a threat model. Record what is at stake and what the component trusts; its reachability, controls, and attack vectors come from the rest of the graph. Applications also record their business logic.

Call again with the same name to update a component — never create a second record for the same thing.`,
    inputSchema: z.object({
      name: z
        .string()
        .describe(
          "Unique component name, e.g. 'Pensar Console (web)', 'Aurora PostgreSQL', 'api.example.com'.",
        ),
      kind: z.enum(COMPONENT_KINDS),
      boundary: z
        .string()
        .describe(
          "Name of the documented boundary its compute or data lives in.",
        ),
      tech: z
        .string()
        .optional()
        .describe(
          "Technology, e.g. 'Next.js 16 on Lambda', 'Aurora PostgreSQL 16 behind RDS Proxy'.",
        ),
      exposure: z
        .enum(["public", "private", "unknown"])
        .describe(
          "public = reachable from the internet; private = only from inside its boundary.",
        ),
      endpoints: z
        .array(z.string())
        .optional()
        .describe("Hostnames or URLs it answers on."),
      usedBy: z
        .array(z.string())
        .optional()
        .describe(
          "Names of documented application components that depend on this one. Omit for applications.",
        ),
      repository: z
        .string()
        .optional()
        .describe(
          "Connected repository whose source backs or defines this component, when confirmed by reading it.",
        ),
      description: z.string().optional(),
      atStake: z
        .string()
        .describe(
          "What this component holds or does that is worth attacking — the data, credentials, privileges, money, or trust an attacker gains by compromising it. Concrete, not generic.",
        ),
      trustAssumptions: z
        .array(z.string())
        .describe(
          "What this component trusts without verifying: callers in a security group, a header set by a proxy, a token's claims, content it ingests, an upstream service. One assumption per entry; empty only when it truly trusts nothing.",
        ),
      businessLogic: z
        .string()
        .optional()
        .describe(
          "For applications: what it does, its actors, and its sensitive operations, fusing wire observations with source. Markdown.",
        ),
      members: z
        .array(z.string())
        .optional()
        .describe("For a collapsed group (e.g. 12 queues), the member names."),
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const boundaries = documented(ctx, "boundary");
      if (!boundaries.has(input.boundary.toLowerCase()))
        return unknownReference(
          "boundary",
          input.boundary,
          boundaries.keys(),
          "Document it with document_boundary first.",
        );
      if (input.usedBy?.length) {
        const applications = new Set(
          [...documented(ctx, "component")]
            .filter(([, record]) => record.kind === "application")
            .map(([name]) => name),
        );
        const missing = firstMissing(input.usedBy, applications);
        if (missing)
          return unknownReference(
            "application",
            missing,
            applications,
            "Document the application with document_component (kind: application) first, or use its exact name.",
          );
      }
      const { toolCallDescription: _, ...record } = input;
      const filepath = writeRecord(ctx, "component", input.name, record);
      return {
        success: true,
        name: input.name,
        kind: input.kind,
        boundary: input.boundary,
        filepath,
        message: `Component '${input.name}' documented`,
      };
    },
  });
}

export function documentFlow(ctx: ToolContext) {
  return tool({
    description: `Document how traffic or data moves between two documented components: e.g. CDN → web app, web app → database, worker → queue, sandbox → egress proxy.

\`from\` and \`to\` are exact component names. Call again with the same from/to/label to update a flow.`,
    inputSchema: z.object({
      from: z
        .string()
        .describe("Name of the documented component traffic originates from."),
      to: z.string().describe("Name of the documented component it reaches."),
      label: z
        .string()
        .describe(
          "Short protocol or purpose, e.g. 'HTTPS', 'RDS Proxy', 'enqueue jobs'.",
        ),
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const components = documented(ctx, "component");
      const missing = firstMissing([input.from, input.to], components);
      if (missing)
        return unknownReference(
          "component",
          missing,
          components.keys(),
          "Document it with document_component first.",
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

export function documentControl(ctx: ToolContext) {
  return tool({
    description: `Document a security control and the layer it protects: a WAF on a distribution, a security group on a subnet tier, an IP allowlist on a route, authentication on an application, tenant isolation in application code, an AUTH token on a cache, an IAM policy on a credential, encryption of stored secrets.

Analyze every layer — edge, account, VPC, subnet, application, datastore, credential — and record what is enforced there. Be concrete about what the control protects and, critically, its gaps: where it does not apply, what an attacker could route around, or what it trusts. A control's gaps are where attack vectors come from.

\`appliesTo\` names the documented boundaries and components the control is enforced on. Call again with the same name to update a control.`,
    inputSchema: z.object({
      name: z
        .string()
        .describe(
          "Unique control name, e.g. 'API WAF', 'Aurora security group', 'Workspace authorization in server actions'.",
        ),
      kind: z.enum(CONTROL_KINDS),
      appliesTo: z
        .array(z.string())
        .min(1)
        .describe(
          "Names of the documented boundaries and components it is enforced on.",
        ),
      protects: z
        .string()
        .describe("What it is meant to stop or guarantee, concretely."),
      gaps: z
        .string()
        .optional()
        .describe(
          "Where it does not apply, what can route around it, what it trusts, or weaknesses observed. Omit only when you found none.",
        ),
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const layers = new Set([
        ...documented(ctx, "boundary").keys(),
        ...documented(ctx, "component").keys(),
      ]);
      const missing = firstMissing(input.appliesTo, layers);
      if (missing)
        return unknownReference(
          "layer",
          missing,
          layers,
          "Document it with document_boundary or document_component first.",
        );
      const { toolCallDescription: _, ...record } = input;
      const filepath = writeRecord(ctx, "control", input.name, record);
      return {
        success: true,
        name: input.name,
        kind: input.kind,
        appliesTo: input.appliesTo,
        filepath,
        message: `Control '${input.name}' documented`,
      };
    },
  });
}

export function documentAttackVector(ctx: ToolContext) {
  return tool({
    description: `Document a theoretical attack vector: a risk the system may have, derived from its controls and grounded in what recon observed or read, for pentest agents to discover and validate.

This is a hypothesis, not a test plan. State what could go wrong, where, why you suspect it, and what it would mean. Do NOT write procedures, commands, payloads, or step lists — the pentest agent working live on the target decides how to confirm it.

A vector usually spans several components (for example sandbox → egress proxy → cloud metadata, or every application that shares a database). List each one in \`components\`.

Call again with the same title to update a vector.`,
    inputSchema: z.object({
      title: z
        .string()
        .describe(
          "Short name of the vector, e.g. 'Sandbox egress escapes containment'.",
        ),
      risk: z
        .string()
        .describe(
          "The theoretical risk in one to three sentences: what could be wrong and how an attacker would benefit.",
        ),
      components: z
        .array(z.string())
        .min(1)
        .describe("Names of the documented components the vector spans."),
      rationale: z
        .string()
        .describe(
          "Why recon suspects it — the specific control, configuration, or code observation that makes it plausible.",
        ),
      impact: z
        .string()
        .describe(
          "What a successful exploit would mean for the business or its tenants.",
        ),
      pattern: z
        .enum(VECTOR_PATTERNS)
        .describe(
          "control-bypass = a path around a documented control; missing-control = a layer with no control where one is expected; trust-abuse = one component trusts another more than it should; shared-resource = one resource serves many tenants or applications; exposure = something reachable that should not be; misconfiguration = a control set up wrongly.",
        ),
      controls: z
        .array(z.string())
        .optional()
        .describe(
          "Names of documented controls this vector bypasses, defeats, or depends on.",
        ),
      priority: z.enum(["high", "medium", "low"]),
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const components = documented(ctx, "component");
      const missingComponent = firstMissing(input.components, components);
      if (missingComponent)
        return unknownReference(
          "component",
          missingComponent,
          components.keys(),
          "Document it with document_component first.",
        );
      const controls = documented(ctx, "control");
      const missingControl = firstMissing(input.controls ?? [], controls);
      if (missingControl)
        return unknownReference(
          "control",
          missingControl,
          controls.keys(),
          "Document it with document_control first.",
        );
      const { toolCallDescription: _, ...record } = input;
      const filepath = writeRecord(ctx, "vector", input.title, record);
      return {
        success: true,
        title: input.title,
        components: input.components,
        priority: input.priority,
        filepath,
        message: `Attack vector '${input.title}' documented`,
      };
    },
  });
}
