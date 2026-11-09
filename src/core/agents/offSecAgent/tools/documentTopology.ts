import { tool } from "ai";
import { z } from "zod";
import { duplicatePairs, likelyDuplicates } from "./topologyDuplicates";
import type { MermaidTopology } from "./topologyMermaid";
import {
  flowKey,
  loadTopology,
  newRecordId,
  type RecordKind,
  type TopologyRecord,
  writeRecord,
} from "./topologyRecords";
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
      detail: z
        .string()
        .describe(
          "State the result from this reference alone. For a live probe, record the host, protocol, ports actually tested and returned state. open|filtered is inconclusive. Put facts from config or inventory in separate source or cloud entries.",
        ),
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

const COLLECTION = {
  boundary: "boundaries",
  component: "components",
  control: "controls",
} as const;

/** Active records of a kind by lower-cased current name, so references can be checked. */
function documented(
  ctx: ToolContext,
  kind: "boundary" | "component" | "control",
): Map<string, TopologyRecord> {
  return new Map(
    loadTopology(ctx.session.rootPath)[COLLECTION[kind]].map((r) => [
      String(r.name).toLowerCase(),
      r,
    ]),
  );
}

function save(
  ctx: ToolContext,
  kind: RecordKind,
  key: string,
  record: TopologyRecord,
): string {
  return writeRecord(ctx.session.rootPath, ctx.session.id, kind, key, record);
}

/**
 * The id a boundary, component, or control write takes: the record named
 * `renameFrom` (a rename keeps identity), else the record already holding
 * `name`, else a new id. Refuses a rename onto a name another record holds.
 */
function identify(
  ctx: ToolContext,
  kind: "boundary" | "component" | "control",
  name: string,
  renameFrom: string | undefined,
  candidate?: Record<string, unknown>,
): { id: string } | { error: Record<string, unknown> } {
  const known = documented(ctx, kind);
  const current = known.get(name.toLowerCase());
  if (!renameFrom && current) return { id: current.id };
  if (!renameFrom) {
    // A new boundary or component that looks like one already documented —
    // often a parallel worker naming the same thing its own way.
    if (candidate && kind !== "control") {
      const matches = likelyDuplicates(kind, { ...candidate, id: "" }, [
        ...known.values(),
      ]);
      if (matches.length)
        return {
          error: {
            success: false,
            error: "possible_duplicate",
            message: `This ${kind} looks like one already documented: ${matches
              .map((m) => `"${m.record.name}" (${m.reason})`)
              .join(
                "; ",
              )}. If it is the same thing, document it under that exact name to update it. If it is different, call again with distinctFrom naming it.`,
            existing: matches.map((m) => m.record.name),
          },
        };
    }
    return { id: newRecordId(kind) };
  }
  const original = known.get(renameFrom.toLowerCase());
  if (!original)
    return {
      error: unknownReference(
        kind,
        renameFrom,
        known.keys(),
        "renameFrom must be the exact current name of a documented record.",
      ),
    };
  if (current && current.id !== original.id)
    return {
      error: {
        success: false,
        error: "name_taken",
        message: `Another ${kind} is already named "${name}". Retire or rename it first.`,
      },
    };
  return { id: original.id };
}

const renameFromSchema = z
  .string()
  .optional()
  .describe(
    "Only to rename: the record's exact current name. It keeps its identity, and everything that references it follows the new name.",
  );

const distinctFromSchema = z
  .array(z.string())
  .optional()
  .describe(
    "Names of documented records this one resembles but is not — only after a possible_duplicate error, when they really are different things.",
  );

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
      renameFrom: renameFromSchema,
      distinctFrom: distinctFromSchema,
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const boundaries = documented(ctx, "boundary");
      const parent = input.parent
        ? boundaries.get(input.parent.toLowerCase())
        : undefined;
      if (input.parent && !parent)
        return unknownReference(
          "boundary",
          input.parent,
          boundaries.keys(),
          "Document the parent boundary first.",
        );
      const identity = identify(
        ctx,
        "boundary",
        input.name,
        input.renameFrom,
        input,
      );
      if ("error" in identity) return identity.error;
      const { toolCallDescription: _, renameFrom: __, ...record } = input;
      const filepath = save(ctx, "boundary", input.name, {
        ...record,
        id: identity.id,
        ...(parent ? { parentId: parent.id } : {}),
      });
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

Every component gets a threat model. Record what is at stake and what the component trusts here; its reachability and controls come from the rest of the graph, and its threats from document_threat. Applications also record their business logic.

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
      renameFrom: renameFromSchema,
      distinctFrom: distinctFromSchema,
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const boundaries = documented(ctx, "boundary");
      const boundary = boundaries.get(input.boundary.toLowerCase());
      if (!boundary)
        return unknownReference(
          "boundary",
          input.boundary,
          boundaries.keys(),
          "Document it with document_boundary first.",
        );
      const applications = new Map(
        [...documented(ctx, "component")].filter(
          ([, record]) => record.kind === "application",
        ),
      );
      if (input.usedBy?.length) {
        const missing = firstMissing(input.usedBy, applications);
        if (missing)
          return unknownReference(
            "application",
            missing,
            applications.keys(),
            "Document the application with document_component (kind: application) first, or use its exact name.",
          );
      }
      const identity = identify(
        ctx,
        "component",
        input.name,
        input.renameFrom,
        input,
      );
      if ("error" in identity) return identity.error;
      const { toolCallDescription: _, renameFrom: __, ...record } = input;
      const filepath = save(ctx, "component", input.name, {
        ...record,
        id: identity.id,
        boundaryId: boundary.id,
        ...(input.usedBy?.length
          ? {
              usedByIds: input.usedBy.map(
                (n) => (applications.get(n.toLowerCase()) as TopologyRecord).id,
              ),
            }
          : {}),
      });
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
      const fromId = (
        components.get(input.from.toLowerCase()) as TopologyRecord
      ).id;
      const toId = (components.get(input.to.toLowerCase()) as TopologyRecord)
        .id;
      const key = flowKey(fromId, toId, input.label);
      // Flows recorded before ids carry names only; resolve those by name.
      const idOf = (name: unknown, id: unknown) =>
        typeof id === "string"
          ? id
          : (components.get(String(name).toLowerCase())?.id ?? "");
      const existing = loadTopology(ctx.session.rootPath).flows.find(
        (f) =>
          flowKey(idOf(f.from, f.fromId), idOf(f.to, f.toId), f.label) === key,
      );
      const { toolCallDescription: _, ...record } = input;
      const filepath = save(
        ctx,
        "flow",
        `${input.from}__${input.to}__${input.label}`,
        {
          ...record,
          id: existing?.id ?? newRecordId("flow"),
          fromId,
          toId,
        },
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
      renameFrom: renameFromSchema,
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const layers = new Map([
        ...documented(ctx, "boundary"),
        ...documented(ctx, "component"),
      ]);
      const missing = firstMissing(input.appliesTo, layers);
      if (missing)
        return unknownReference(
          "layer",
          missing,
          layers.keys(),
          "Document it with document_boundary or document_component first.",
        );
      const identity = identify(ctx, "control", input.name, input.renameFrom);
      if ("error" in identity) return identity.error;
      const { toolCallDescription: _, renameFrom: __, ...record } = input;
      const filepath = save(ctx, "control", input.name, {
        ...record,
        id: identity.id,
        appliesToIds: input.appliesTo.map(
          (n) => (layers.get(n.toLowerCase()) as TopologyRecord).id,
        ),
      });
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

/** Third-party services the system relies on but cannot be attacked through directly. */
const UNTHREATENED_KINDS = new Set([
  "saas",
  "identity-provider",
  "llm-provider",
]);

export const THREAT_CATEGORIES = [
  "spoofing",
  "tampering",
  "repudiation",
  "information-disclosure",
  "denial-of-service",
  "elevation-of-privilege",
] as const;

export function documentThreat(ctx: ToolContext) {
  return tool({
    description: `Document one threat to a component: a concrete way this system could be attacked through it. A component's threat model is the set of its threats, together with what is at stake, what it trusts, how it is reached, and its controls.

Name the attacker's starting privilege, the control it should encounter, and the outcome beyond that privilege. A confirmation must distinguish the attack from normal authorized behavior. For example, an approved bump to a pinned dependency proves that the dependency runs; a supply-chain threat needs a path for an attacker to bypass that pin, review, or release authority. Keep expected access and deployment behavior in the component's trust assumptions when that is all the evidence shows.

Model each component in depth. Work through every STRIDE category against what the map shows — its trust assumptions, the gaps in the controls on it and on the layers around it, the flows that reach it and the ones it makes, and what it holds — and document each threat that plausibly applies. Most components on an attack path have several. Write each one for this system specifically: who acts, through which entry point and flow, using which trust assumption or control gap, and what they get. A generic threat ("SQL injection is possible") is not a threat model.

A pentest agent takes each threat as an objective and tests it live, so make it testable: the exact place the attack starts, the steps, and how to confirm it. A threat a tester cannot act on is not finished.

Document the same title on the same component again to update it.`,
    inputSchema: z.object({
      component: z
        .string()
        .describe("Exact name of the documented component the threat targets."),
      title: z
        .string()
        .describe(
          "Short, specific title, unique within the component, e.g. 'Read any account through legacy v1 IDs'.",
        ),
      category: z.enum(THREAT_CATEGORIES),
      entryPoint: z
        .string()
        .describe(
          "Where the attack starts, concretely enough to send a request to: a host plus method and route, and the parameter, header, cookie, or field involved — e.g. 'POST https://app.example.com/api/v1/orders, body.accountId'. For a non-HTTP surface: the queue, bucket, function URL, or API call.",
        ),
      scenario: z
        .string()
        .describe(
          "Who does what, through which entry point and flow, exploiting which trust assumption or control gap, with what result — concrete to this system.",
        ),
      attackSteps: z
        .array(z.string())
        .min(2)
        .describe(
          "The attack in order, one action per step, as a tester would carry it out: what to request or do, with which values, and what each step yields for the next.",
        ),
      preconditions: z
        .array(z.string())
        .describe(
          "What the attacker needs: network position, an account, a leaked key, a victim action. Empty when anyone on the internet can do it.",
        ),
      impact: z
        .string()
        .describe(
          "What is lost and how widely: whose data, which privileges, how much money or availability.",
        ),
      severity: z
        .enum(["critical", "high", "medium", "low"])
        .describe(
          "How bad it is if it holds, from the impact: critical for cross-tenant data, account takeover, or code execution; high for one tenant's sensitive data or privileged actions; medium for limited data or abuse; low for minor disclosure.",
        ),
      likelihood: z.enum(["low", "medium", "high"]),
      likelihoodRationale: z
        .string()
        .describe(
          "Why that likelihood: exposure, ease, what stands in the way, whether it was confirmed.",
        ),
      controls: z
        .array(z.string())
        .describe(
          "Names of documented controls that should stop it — the threat usually exploits their gaps. Empty only when no documented control stands in the way; then say so in likelihoodRationale.",
        ),
      verification: z
        .string()
        .describe(
          "How a pentest confirms it without causing harm: the request(s) to send and the response, data, or side effect that proves the threat holds — and what result shows it does not.",
        ),
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const components = documented(ctx, "component");
      const component = components.get(input.component.toLowerCase());
      if (!component)
        return unknownReference(
          "component",
          input.component,
          components.keys(),
          "Document the component first, or use its exact name.",
        );
      const controls = documented(ctx, "control");
      const missing = firstMissing(input.controls ?? [], controls);
      if (missing)
        return unknownReference(
          "control",
          missing,
          controls.keys(),
          "Document the control with document_control first, or use its exact name.",
        );
      const existing = loadTopology(ctx.session.rootPath).threats.find(
        (t) =>
          (t.componentId === component.id ||
            String(t.component).toLowerCase() ===
              String(component.name).toLowerCase()) &&
          String(t.title).toLowerCase() === input.title.toLowerCase(),
      );
      const { toolCallDescription: _, ...record } = input;
      const filepath = save(
        ctx,
        "threat",
        `${component.name}__${input.title}`,
        {
          ...record,
          id: existing?.id ?? newRecordId("threat"),
          component: component.name,
          componentId: component.id,
          ...(input.controls?.length
            ? {
                controlIds: input.controls.map(
                  (n) => (controls.get(n.toLowerCase()) as TopologyRecord).id,
                ),
              }
            : {}),
        },
      );
      return {
        success: true,
        component: component.name,
        title: input.title,
        filepath,
        message: `Threat '${input.title}' documented on '${component.name}'`,
      };
    },
  });
}

/** Fields update_record may change, per kind; everything else carries forward verbatim. */
const UPDATABLE: Record<
  "boundary" | "component" | "control" | "threat",
  readonly string[]
> = {
  boundary: ["kind", "provider", "parent", "description"],
  component: [
    "kind",
    "boundary",
    "tech",
    "exposure",
    "endpoints",
    "usedBy",
    "repository",
    "description",
    "atStake",
    "trustAssumptions",
    "businessLogic",
    "members",
  ],
  control: ["kind", "appliesTo", "protects", "gaps"],
  threat: [
    "category",
    "entryPoint",
    "scenario",
    "attackSteps",
    "preconditions",
    "impact",
    "severity",
    "likelihood",
    "likelihoodRationale",
    "controls",
    "verification",
  ],
};

export function updateRecord(ctx: ToolContext) {
  return tool({
    description: `Change specific fields of a documented boundary, component, control, or threat, leaving every other field exactly as it is. In an update run this is how a record changes: pass only what the change affects (e.g. a component's exposure and endpoints, a control's gaps), with evidence for the change.

Do not use it to restate a record in new words, and do not touch a record whose facts did not change. Rename with document_* and renameFrom; remove with retire_record.`,
    inputSchema: z.object({
      kind: z.enum(["boundary", "component", "control", "threat"]),
      name: z
        .string()
        .describe("Exact current name of the record; for a threat, its title."),
      component: z
        .string()
        .optional()
        .describe("For a threat: the exact name of its component."),
      changes: z
        .object({
          kind: z.string().optional(),
          provider: z.string().optional(),
          parent: z.string().optional(),
          boundary: z.string().optional(),
          tech: z.string().optional(),
          exposure: z.enum(["public", "private", "unknown"]).optional(),
          endpoints: z.array(z.string()).optional(),
          usedBy: z.array(z.string()).optional(),
          repository: z.string().optional(),
          description: z.string().optional(),
          atStake: z.string().optional(),
          trustAssumptions: z.array(z.string()).optional(),
          businessLogic: z.string().optional(),
          members: z.array(z.string()).optional(),
          appliesTo: z.array(z.string()).optional(),
          protects: z.string().optional(),
          gaps: z.string().optional(),
          category: z.enum(THREAT_CATEGORIES).optional(),
          entryPoint: z.string().optional(),
          scenario: z.string().optional(),
          attackSteps: z.array(z.string()).optional(),
          preconditions: z.array(z.string()).optional(),
          impact: z.string().optional(),
          severity: z.enum(["critical", "high", "medium", "low"]).optional(),
          likelihood: z.enum(["low", "medium", "high"]).optional(),
          likelihoodRationale: z.string().optional(),
          controls: z.array(z.string()).optional(),
          verification: z.string().optional(),
        })
        .describe("Only the fields that changed, with their new values."),
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      let record: TopologyRecord | undefined;
      if (input.kind === "threat") {
        const threats = loadTopology(ctx.session.rootPath).threats;
        record = threats.find(
          (t) =>
            String(t.component).toLowerCase() ===
              input.component?.toLowerCase() &&
            String(t.title).toLowerCase() === input.name.toLowerCase(),
        );
        if (!record)
          return unknownReference(
            "threat",
            `${input.component}: ${input.name}`,
            threats.map((t) => `${t.component}: ${t.title}`),
            "Give the threat's exact component and title.",
          );
      } else {
        const known = documented(ctx, input.kind);
        record = known.get(input.name.toLowerCase());
        if (!record)
          return unknownReference(
            input.kind,
            input.name,
            known.keys(),
            "Give the exact current name.",
          );
      }
      const changes = Object.fromEntries(
        Object.entries(input.changes).filter(([, v]) => v !== undefined),
      ) as Record<string, unknown>;
      const fields = Object.keys(changes);
      if (!fields.length)
        return {
          success: false,
          error: "no_changes",
          message: "Pass at least one changed field.",
        };
      const invalid = fields.filter((f) => !UPDATABLE[input.kind].includes(f));
      if (invalid.length)
        return {
          success: false,
          error: "invalid_field",
          message: `A ${input.kind} has no updatable field ${invalid.join(", ")}. Updatable: ${UPDATABLE[input.kind].join(", ")}.`,
        };
      const kinds = {
        boundary: BOUNDARY_KINDS as readonly string[],
        component: COMPONENT_KINDS as readonly string[],
        control: CONTROL_KINDS as readonly string[],
        threat: [] as readonly string[],
      }[input.kind];
      if (changes.kind !== undefined && !kinds.includes(String(changes.kind)))
        return {
          success: false,
          error: "invalid_kind",
          message: `kind must be one of ${kinds.join(", ")}.`,
        };

      const resolved: Record<string, unknown> = {};
      const boundaries = documented(ctx, "boundary");
      const components = documented(ctx, "component");
      const one = (
        map: Map<string, TopologyRecord>,
        name: unknown,
        what: string,
        fix: string,
      ) => {
        const found = map.get(String(name).toLowerCase());
        return found
          ? { found }
          : { error: unknownReference(what, String(name), map.keys(), fix) };
      };
      if (changes.parent !== undefined) {
        const r = one(
          boundaries,
          changes.parent,
          "boundary",
          "Document the parent boundary first.",
        );
        if ("error" in r) return r.error;
        resolved.parentId = r.found.id;
      }
      if (changes.boundary !== undefined) {
        const r = one(
          boundaries,
          changes.boundary,
          "boundary",
          "Document it with document_boundary first.",
        );
        if ("error" in r) return r.error;
        resolved.boundaryId = r.found.id;
      }
      if (changes.usedBy !== undefined) {
        const apps = new Map(
          [...components].filter(([, c]) => c.kind === "application"),
        );
        const ids: string[] = [];
        for (const n of changes.usedBy as string[]) {
          const r = one(
            apps,
            n,
            "application",
            "Use the exact name of a documented application.",
          );
          if ("error" in r) return r.error;
          ids.push(r.found.id);
        }
        resolved.usedByIds = ids;
      }
      if (changes.appliesTo !== undefined) {
        const layers = new Map([...boundaries, ...components]);
        const ids: string[] = [];
        for (const n of changes.appliesTo as string[]) {
          const r = one(
            layers,
            n,
            "layer",
            "Document it with document_boundary or document_component first.",
          );
          if ("error" in r) return r.error;
          ids.push(r.found.id);
        }
        resolved.appliesToIds = ids;
      }
      if (changes.controls !== undefined) {
        const controls = documented(ctx, "control");
        const ids: string[] = [];
        for (const n of changes.controls as string[]) {
          const r = one(
            controls,
            n,
            "control",
            "Use the exact name of a documented control.",
          );
          if ("error" in r) return r.error;
          ids.push(r.found.id);
        }
        resolved.controlIds = ids;
      }
      const prior = Array.isArray(record.evidence) ? record.evidence : [];
      const key =
        input.kind === "threat"
          ? `${record.component}__${record.title}`
          : String(record.name);
      const displayName = input.kind === "threat" ? record.title : record.name;
      const filepath = save(ctx, input.kind, key, {
        ...record,
        ...changes,
        ...resolved,
        evidence: [...prior, ...input.evidence],
      });
      return {
        success: true,
        kind: input.kind,
        name: displayName,
        changed: fields,
        filepath,
        message: `Updated ${input.kind} '${displayName}': ${fields.join(", ")}`,
      };
    },
  });
}

export function retireRecord(ctx: ToolContext) {
  return tool({
    description: `Retire a boundary, component, flow, control, or threat that no longer exists or no longer applies — the only way to remove something from the map. Use it in an update run when evidence shows the thing is gone: a host that no longer resolves or answers, a resource removed from IaC or absent from the cloud inventory, a route deleted from code.

Never retire something only because you did not look at it again, or to replace it with a renamed record (rename with renameFrom instead). Retiring a component does not retire its flows or controls; review_topology lists the ones left pointing at it.`,
    inputSchema: z.object({
      kind: z.enum(["boundary", "component", "flow", "control", "threat"]),
      name: z
        .string()
        .optional()
        .describe(
          "Exact current name, for a boundary, component, or control; for a threat, its title.",
        ),
      component: z.string().optional().describe("For a threat: its component."),
      from: z.string().optional().describe("For a flow: its source component."),
      to: z.string().optional().describe("For a flow: its target component."),
      label: z.string().optional().describe("For a flow: its label."),
      reason: z
        .string()
        .describe(
          "What shows it is gone, e.g. 'api-old.example.com no longer resolves', 'queue removed from infra/queues.ts in abc123'.",
        ),
      evidence: evidenceSchema,
      toolCallDescription,
    }),
    execute: async (input) => {
      const topology = loadTopology(ctx.session.rootPath);
      let record: TopologyRecord | undefined;
      if (input.kind === "flow") {
        record = topology.flows.find(
          (f) =>
            String(f.from).toLowerCase() === input.from?.toLowerCase() &&
            String(f.to).toLowerCase() === input.to?.toLowerCase() &&
            String(f.label ?? "").toLowerCase() ===
              (input.label ?? "").toLowerCase(),
        );
        if (!record)
          return unknownReference(
            "flow",
            `${input.from} → ${input.to} (${input.label})`,
            topology.flows.map((f) => `${f.from} → ${f.to} (${f.label})`),
            "Give the flow's exact from, to, and label.",
          );
      } else if (input.kind === "threat") {
        record = topology.threats.find(
          (t) =>
            String(t.component).toLowerCase() ===
              input.component?.toLowerCase() &&
            String(t.title).toLowerCase() === input.name?.toLowerCase(),
        );
        if (!record)
          return unknownReference(
            "threat",
            `${input.component}: ${input.name}`,
            topology.threats.map((t) => `${t.component}: ${t.title}`),
            "Give the threat's exact component and title.",
          );
      } else {
        const known = documented(ctx, input.kind);
        record = input.name ? known.get(input.name.toLowerCase()) : undefined;
        if (!record)
          return unknownReference(
            input.kind,
            input.name ?? "",
            known.keys(),
            "Give the exact current name.",
          );
      }
      const name =
        input.kind === "flow"
          ? `${record.from}__${record.to}__${record.label}`
          : input.kind === "threat"
            ? `${record.component}__${record.title}`
            : String(record.name);
      const filepath = save(ctx, input.kind, name, {
        ...record,
        status: "retired",
        retiredReason: input.reason,
        evidence: input.evidence,
      });
      return {
        success: true,
        kind: input.kind,
        id: record.id,
        filepath,
        message: `Retired ${input.kind} '${name.replace(/__/g, " → ")}'`,
      };
    },
  });
}

export function mergeRecords(ctx: ToolContext) {
  return tool({
    description: `Fold a duplicate boundary or component into the record that should remain — for two records documented under different names for one thing (review_topology reports likely pairs as possible-duplicate).

Everything that pointed at the duplicate moves to the kept record: flows (a flow that becomes a copy of one the kept record already has is retired), controls, the applications that use it, and — for a boundary — the components and boundaries inside it. The duplicate is then retired. Document the kept record again afterwards if the duplicate held details it lacks.`,
    inputSchema: z.object({
      kind: z.enum(["boundary", "component"]),
      keep: z.string().describe("Exact name of the record to keep."),
      duplicate: z
        .string()
        .describe("Exact name of the record to fold into it and retire."),
      toolCallDescription,
    }),
    execute: async (input) => {
      const known = documented(ctx, input.kind);
      const keep = known.get(input.keep.toLowerCase());
      const dup = known.get(input.duplicate.toLowerCase());
      if (!keep || !dup)
        return unknownReference(
          input.kind,
          keep ? input.duplicate : input.keep,
          known.keys(),
          "Give the exact current names of both records.",
        );
      if (keep.id === dup.id)
        return {
          success: false,
          error: "same_record",
          message: "keep and duplicate are the same record.",
        };
      const topology = loadTopology(ctx.session.rootPath);
      const isDup = (id: unknown, name: unknown) =>
        id === dup.id ||
        (id === undefined &&
          String(name).toLowerCase() === String(dup.name).toLowerCase());
      const swap = (ids: unknown, names: unknown) => {
        const nameList = Array.isArray(names) ? names.map(String) : [];
        const idList = Array.isArray(ids)
          ? ids.map(String)
          : nameList.map(() => undefined);
        const pairs = nameList.map((n, i) =>
          isDup(idList[i], n) ? [keep.id, String(keep.name)] : [idList[i], n],
        );
        const seen = new Set<string>();
        const kept = pairs.filter(([id, n]) => {
          const k = String(id ?? n).toLowerCase();
          if (seen.has(k)) return false;
          seen.add(k);
          return true;
        });
        return { ids: kept.map(([id]) => id), names: kept.map(([, n]) => n) };
      };
      let moved = 0;
      let retiredFlows = 0;

      if (input.kind === "component") {
        const keys = new Set(
          topology.flows
            .filter((f) => !isDup(f.fromId, f.from) && !isDup(f.toId, f.to))
            .map((f) =>
              flowKey(
                String(f.fromId ?? f.from),
                String(f.toId ?? f.to),
                f.label,
              ),
            ),
        );
        for (const f of topology.flows) {
          const fromDup = isDup(f.fromId, f.from);
          const toDup = isDup(f.toId, f.to);
          if (!fromDup && !toDup) continue;
          const fromId = fromDup ? keep.id : f.fromId;
          const toId = toDup ? keep.id : f.toId;
          const key = flowKey(
            String(fromId ?? f.from),
            String(toId ?? f.to),
            f.label,
          );
          const name = `${f.from}__${f.to}__${f.label}`;
          if (fromId === toId || keys.has(key)) {
            save(ctx, "flow", name, {
              ...f,
              status: "retired",
              retiredReason: `Merged into "${keep.name}"`,
            });
            retiredFlows++;
            continue;
          }
          keys.add(key);
          save(ctx, "flow", name, {
            ...f,
            ...(fromDup ? { from: keep.name, fromId: keep.id } : {}),
            ...(toDup ? { to: keep.name, toId: keep.id } : {}),
          });
          moved++;
        }
        for (const c of topology.components) {
          if (
            c.id === dup.id ||
            !(
              Array.isArray(c.usedBy) &&
              c.usedBy.some((n, i) =>
                isDup((c.usedByIds as unknown[] | undefined)?.[i], n),
              )
            )
          )
            continue;
          const { ids, names } = swap(c.usedByIds, c.usedBy);
          save(ctx, "component", String(c.name), {
            ...c,
            usedBy: names,
            usedByIds: ids,
          });
          moved++;
        }
      } else {
        for (const c of topology.components)
          if (isDup(c.boundaryId, c.boundary)) {
            save(ctx, "component", String(c.name), {
              ...c,
              boundary: keep.name,
              boundaryId: keep.id,
            });
            moved++;
          }
        for (const b of topology.boundaries)
          if (
            b.id !== dup.id &&
            b.parent !== undefined &&
            isDup(b.parentId, b.parent)
          ) {
            save(ctx, "boundary", String(b.name), {
              ...b,
              parent: keep.name,
              parentId: keep.id,
            });
            moved++;
          }
      }
      for (const c of topology.controls) {
        const ids = c.appliesToIds as unknown[] | undefined;
        if (
          !(
            Array.isArray(c.appliesTo) &&
            c.appliesTo.some((n, i) => isDup(ids?.[i], n))
          )
        )
          continue;
        const swapped = swap(c.appliesToIds, c.appliesTo);
        save(ctx, "control", String(c.name), {
          ...c,
          appliesTo: swapped.names,
          appliesToIds: swapped.ids,
        });
        moved++;
      }
      if (input.kind === "component") {
        const keptTitles = new Set(
          topology.threats
            .filter((t) => t.componentId === keep.id)
            .map((t) => String(t.title).toLowerCase()),
        );
        for (const t of topology.threats) {
          if (!isDup(t.componentId, t.component)) continue;
          const key = `${t.component}__${t.title}`;
          if (keptTitles.has(String(t.title).toLowerCase())) {
            save(ctx, "threat", key, {
              ...t,
              status: "retired",
              retiredReason: `Merged into "${keep.name}"`,
            });
            continue;
          }
          keptTitles.add(String(t.title).toLowerCase());
          save(ctx, "threat", key, {
            ...t,
            component: keep.name,
            componentId: keep.id,
          });
          moved++;
        }
      }
      save(ctx, input.kind, String(dup.name), {
        ...dup,
        status: "retired",
        retiredReason: `Merged into "${keep.name}"`,
      });
      return {
        success: true,
        kept: keep.name,
        retired: dup.name,
        referencesMoved: moved,
        flowsRetired: retiredFlows,
        message: `Merged '${dup.name}' into '${keep.name}': ${moved} reference(s) moved, ${retiredFlows} duplicate flow(s) retired.`,
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
    | "references-retired"
    | "possible-duplicate"
    | "no-threats"
    | "threat-untestable"
    | "unconnected";
  subject: string;
  fix: string;
}

/** Deterministic checks over the documented topology. */
export function reviewTopologyRecords(ctx: ToolContext): TopologyIssue[] {
  const topology = loadTopology(ctx.session.rootPath);
  const boundaries = topology.boundaries;
  const components = topology.components;
  const flows = topology.flows;
  const lower = (v: unknown) => String(v ?? "").toLowerCase();
  const retired = new Set(
    topology.retired
      .filter((r) => r.kind === "component" || r.kind === "boundary")
      .map((r) => lower(r.record.name)),
  );
  const pointsAtRetired = (names: unknown[]) =>
    names.find((n) => retired.has(lower(n)));
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
  for (const f of flows) {
    const gone = pointsAtRetired([f.from, f.to]);
    if (gone)
      issues.push({
        check: "references-retired",
        subject: `${f.from} → ${f.to} (${f.label})`,
        fix: `It reaches the retired '${gone}': retire the flow too, or document the component again if it still exists.`,
      });
  }
  for (const c of topology.controls) {
    const gone = pointsAtRetired(Array.isArray(c.appliesTo) ? c.appliesTo : []);
    if (gone)
      issues.push({
        check: "references-retired",
        subject: String(c.name),
        fix: `It applies to the retired '${gone}': update appliesTo, or retire the control if nothing it protects remains.`,
      });
  }
  for (const t of topology.threats) {
    const gone = pointsAtRetired([t.component]);
    if (gone)
      issues.push({
        check: "references-retired",
        subject: `${t.component}: ${t.title}`,
        fix: `It targets the retired '${gone}': retire the threat. If the scenario applies elsewhere, document it on the surviving component.`,
      });
  }
  const threatened = new Set(topology.threats.map((t) => lower(t.component)));
  for (const c of components)
    if (
      !UNTHREATENED_KINDS.has(String(c.kind)) &&
      !threatened.has(lower(c.name))
    )
      issues.push({
        check: "no-threats",
        subject: String(c.name),
        fix: "Threat-model it with document_threat: work through each STRIDE category against its trust assumptions, its controls' gaps, and its flows.",
      });
  const has = (v: unknown) => typeof v === "string" && v.trim().length > 0;
  for (const t of topology.threats) {
    const missing = [
      !has(t.entryPoint) && "entry point",
      !(Array.isArray(t.attackSteps) && t.attackSteps.length) && "attack steps",
      !has(t.severity) && "severity",
      !has(t.verification) && "verification",
    ].filter(Boolean);
    if (missing.length)
      issues.push({
        check: "threat-untestable",
        subject: `${t.component}: ${t.title}`,
        fix: `A pentest cannot act on it yet. update_record it with its ${missing.join(", ")}.`,
      });
  }
  for (const kind of ["boundary", "component"] as const)
    for (const p of duplicatePairs(
      kind,
      kind === "boundary" ? boundaries : components,
    ))
      issues.push({
        check: "possible-duplicate",
        subject: `${p.a.name} / ${p.b.name}`,
        fix: `They look like one ${kind} (${p.reason}). If they are, merge_records keeps one and folds the other into it; if not, document one again with distinctFrom naming the other.`,
      });
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

/** The active documented topology in a session, references resolved to current names. */
export function readDocumentedTopology(sessionRoot: string): MermaidTopology {
  const topology = loadTopology(sessionRoot);
  const latest = (kind: "boundary" | "component" | "control") =>
    topology[COLLECTION[kind]];
  const optional = (v: unknown) => (v == null ? undefined : String(v));
  return {
    boundaries: latest("boundary").map((r) => ({
      name: String(r.name),
      kind: String(r.kind),
      parent: optional(r.parent),
    })),
    components: latest("component").map((r) => ({
      name: String(r.name),
      kind: String(r.kind),
      boundary: String(r.boundary),
      exposure: optional(r.exposure),
    })),
    flows: topology.flows.map((r) => ({
      from: String(r.from),
      to: String(r.to),
      label: optional(r.label),
    })),
    controls: latest("control").map((r) => ({
      name: String(r.name),
      appliesTo: Array.isArray(r.appliesTo) ? r.appliesTo.map(String) : [],
      gaps: optional(r.gaps),
    })),
  };
}

/**
 * What a recon worker is told about the map when it is spawned, so it adds
 * to the records the orchestrator and other workers made instead of
 * documenting the same things under its own names.
 */
export function describeMapForWorker(sessionRoot: string): string {
  const topology = loadTopology(sessionRoot);
  if (!topology.boundaries.length && !topology.components.length) return "";
  const line = (r: TopologyRecord, where: unknown) =>
    `- ${r.name} (${r.kind}${where ? `, in ${where}` : ""})`;
  return `## Already documented
These records exist. Reuse their exact names: document one again under the same name to add to it, and attach flows and controls to these names. Create a record only for something not listed — never a second record for one of these under another name.
Boundaries:
${topology.boundaries.map((b) => line(b, b.parent)).join("\n") || "- none"}
Components:
${topology.components.map((c) => line(c, c.boundary)).join("\n") || "- none"}`;
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
  const flows = loadTopology(sessionRoot).flows.length;
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
