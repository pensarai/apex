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
 * boundaries contain components, flows connect components, and controls
 * apply to boundaries and components. They record facts only — pentest
 * agents form their own hypotheses from this map with live access.
 *
 * A component's threat model is composed rather than written as prose: the
 * agent records what is at stake and what the component trusts, and the
 * consumer derives reachability and controls from the graph.
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
  "user-device",
] as const;

export const COMPONENT_KINDS = [
  "application",
  "client",
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

type RecordKind = "boundary" | "component" | "flow" | "control";

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
    description: `Document a boundary that contains components: an edge network (CDN, Cloudflare), a cloud account, a region, a VPC, a subnet tier, the set of third-party services the system relies on, or the user devices its distributed clients run on (user-device: whoever holds the device controls the client).

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
    description: `Document a component of the system on an attack path: an application users or attackers reach, or anything applications are reached through or that attacker-influenced data flows into — entry points (CDN distributions, load balancers, API gateways, function URLs, MQTT endpoints), databases, caches, queues, object stores, brokers, shared workers, identity providers, LLM providers, SaaS. Supporting infrastructure nothing attacker-influenced flows into (secret stores, key management, deploy roles, alerting, log forwarding, housekeeping jobs) is not a component.

A client is software the organization distributes that runs on users' devices — a mobile or desktop app, a browser extension, a CLI. Document it in a user-device boundary: anyone can obtain and inspect it, so what it ships (hosts, keys, flags) is public, and its own controls (transport security, exported components, deep-link handling, embedded secrets) belong on it. Its endpoints are the URL schemes and app links it handles; connect it with flows to the components it calls. A web frontend served by an application is part of that application, not a client.

Document components even when they are not reachable from the origin — a database in a private subnet is part of the surface. Its evidence will then be 'source' (IaC, config, code) or 'inferred', not 'observed'.

Every component gets a threat model. Record what is at stake and what the component trusts; its reachability and controls come from the rest of the graph. Applications also record their business logic.

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
        .describe(
          "Hostnames or URLs it answers on; for a client, the URL schemes and app links it handles (e.g. 'example://pay').",
        ),
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

Analyze every layer — edge, account, VPC, subnet, application, datastore, credential — and record what is enforced there. Be concrete about what the control protects and, critically, its gaps: where it does not apply, what an attacker could route around, or what it trusts. A control's gaps are the most valuable context a pentest agent receives.

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

/** One problem `review_topology` found, with the fix it expects. */
export interface TopologyIssue {
  check:
    | "placed-at-vpc-level"
    | "vpc-without-subnets"
    | "names-two-parts"
    | "public-without-host"
    | "client-off-device"
    | "unconnected";
  subject: string;
  fix: string;
}

function latestRecords(
  ctx: ToolContext,
  prefix: string,
): Record<string, unknown>[] {
  const dir = topologyDir(ctx);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.startsWith(prefix) && f.endsWith(".json"))
    .sort()
    .map(
      (f) =>
        JSON.parse(readFileSync(join(dir, f), "utf8")) as Record<
          string,
          unknown
        >,
    );
}

/** Deterministic checks over the documented topology. */
export function reviewTopologyRecords(ctx: ToolContext): TopologyIssue[] {
  const boundaries = [...documented(ctx, "boundary").values()];
  const components = [...documented(ctx, "component").values()];
  const flows = latestRecords(ctx, "flow_");
  const lower = (v: unknown) => String(v ?? "").toLowerCase();
  const subnetParents = new Set(
    boundaries.filter((b) => b.kind === "subnet").map((b) => lower(b.parent)),
  );
  const vpcs = new Set(
    boundaries.filter((b) => b.kind === "vpc").map((b) => lower(b.name)),
  );
  const devices = new Set(
    boundaries
      .filter((b) => b.kind === "user-device")
      .map((b) => lower(b.name)),
  );
  const flowEnds = new Set(flows.flatMap((f) => [lower(f.from), lower(f.to)]));
  const issues: TopologyIssue[] = [];

  for (const vpc of vpcs)
    if (!subnetParents.has(vpc))
      issues.push({
        check: "vpc-without-subnets",
        subject: vpc,
        fix: "Document its subnet tiers (at least public and private) and move its components into them.",
      });
  for (const c of components) {
    const name = String(c.name);
    if (vpcs.has(lower(c.boundary)) && subnetParents.has(lower(c.boundary)))
      issues.push({
        check: "placed-at-vpc-level",
        subject: name,
        fix: "Place it in the subnet tier where it runs (public for internet-facing load balancers, NAT, elastic IPs; private for functions, containers, datastores).",
      });
    if (/\s\+\s/.test(name))
      issues.push({
        check: "names-two-parts",
        subject: name,
        fix: "If the parts run in different boundaries (e.g. a Worker and the Lambda behind it), document each as its own component and connect them with a flow.",
      });
    if (
      c.exposure === "public" &&
      (c.kind === "entrypoint" || c.kind === "application") &&
      !(Array.isArray(c.endpoints) && c.endpoints.length)
    )
      issues.push({
        check: "public-without-host",
        subject: name,
        fix: "Record its concrete host — a pentest cannot be scoped to it otherwise.",
      });
    if ((c.kind === "client") !== devices.has(lower(c.boundary)))
      issues.push({
        check: "client-off-device",
        subject: name,
        fix:
          c.kind === "client"
            ? "Place the client in a user-device boundary — it runs on users' devices, not in the organization's infrastructure."
            : "Only clients live in a user-device boundary; place it where it runs, or document it as a client.",
      });
    if (!flowEnds.has(lower(name)))
      issues.push({
        check: "unconnected",
        subject: name,
        fix: "Document the flows that reach it and that it makes, or remove it if it is not on an attack path.",
      });
  }
  return issues;
}

export function reviewTopology(ctx: ToolContext) {
  return tool({
    description: `Check the documented topology for structural problems before finalizing: VPCs without subnet tiers, components placed at the VPC level instead of a subnet, components whose name joins two parts, public entry points and applications without a concrete host, clients outside a user-device boundary (or other components inside one), and components with no flows.

Resolve every issue by documenting again with the same name (or splitting a component in two), then call review_topology again until it reports none or the remaining ones are explained in the component's description.`,
    inputSchema: z.object({ toolCallDescription }),
    execute: async () => {
      const issues = reviewTopologyRecords(ctx);
      return {
        success: true,
        issueCount: issues.length,
        issues,
        message: issues.length
          ? `${issues.length} topology issue(s) to resolve`
          : "No topology issues found",
      };
    },
  });
}

/**
 * What a session has documented so far, for a continuation pass that picks up
 * where an earlier pass stopped.
 */
export function describeDocumentedTopology(
  sessionRoot: string,
  pass: number,
): string {
  const ctx = { session: { rootPath: sessionRoot } } as ToolContext;
  const names = (kind: "boundary" | "component" | "control") =>
    [...documented(ctx, kind).values()].map((r) => String(r.name));
  const flows = latestRecords(ctx, "flow_").length;
  const issues = reviewTopologyRecords(ctx);
  const list = (items: string[]) => (items.length ? items.join("; ") : "none");
  return `## Continue (pass ${pass + 1})
An earlier pass stopped before calling create_attack_surface_report. Everything it documented is kept; do not re-document it unless you are correcting it, and do not start over.
- Boundaries: ${list(names("boundary"))}
- Components: ${list(names("component"))}
- Controls: ${list(names("control"))}
- Flows: ${flows}
- review_topology issues: ${issues.length ? issues.map((i) => `${i.check}: ${i.subject}`).join("; ") : "none"}
Pick up from here: finish mapping the components, flows, and controls that are still missing, resolve the review_topology issues, then call create_attack_surface_report. Keep calling tools until the report is written.`;
}
