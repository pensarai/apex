import type {
  LoadedTopology,
  RecordKind,
  TopologyRecord,
} from "../../../../src/core/agents/offSecAgent/tools/topologyRecords";
import {
  type SurfaceEntry,
  surfaceKey,
  surfaceText,
} from "../attack-surface-model";
import type {
  Boundary,
  Component,
  Control,
  Evidence,
  Threat,
  Topology,
} from "./types";

export interface SessionTopology {
  topology: Topology;
  entries: Map<string, SurfaceEntry>;
  warnings: string[];
}

const UNPLACED = "__unplaced";
const strings = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

function evidence(value: unknown): Evidence[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item: unknown) => {
    if (!item || typeof item !== "object") return [];
    const record = item as Record<string, unknown>;
    const source = record.source;
    if (
      source !== "observed" &&
      source !== "cloud" &&
      source !== "source" &&
      source !== "inferred"
    )
      return [];
    return [
      {
        source,
        detail: surfaceText(record.detail),
        ref: surfaceText(record.ref) || undefined,
      },
    ];
  });
}

export function adaptSessionTopology(loaded: LoadedTopology): SessionTopology {
  const entries = new Map<string, SurfaceEntry>();
  const warnings: string[] = [];
  function oneOf<const T extends string>(
    value: unknown,
    choices: readonly T[],
    fallback: T,
  ): T {
    const match = choices.find((choice) => choice === value);
    if (!match && value !== undefined && value !== null && value !== "")
      warnings.push(
        `Unsupported classification “${String(value)}”; rendered as “${fallback}”. Original values remain in record details.`,
      );
    return match ?? fallback;
  }

  const collections = [
    ["boundary", loaded.boundaries],
    ["component", loaded.components],
    ["flow", loaded.flows],
    ["control", loaded.controls],
    ["threat", loaded.threats],
  ] as const;
  for (const [kind, records] of collections)
    for (const record of records) {
      const entry: SurfaceEntry = { kind, record, depth: 0 };
      entries.set(surfaceKey(entry), entry);
    }

  const lookup = (kinds: RecordKind[]) => {
    const candidates = [...entries.entries()].filter(([, entry]) =>
      kinds.includes(entry.kind),
    );
    return (id: unknown, name: unknown): string | undefined => {
      const explicit = surfaceText(id);
      const matches = candidates.filter(([, entry]) =>
        explicit
          ? entry.record.id === explicit
          : surfaceText(name) &&
            surfaceText(entry.record.name).toLowerCase() ===
              surfaceText(name).toLowerCase(),
      );
      return matches.length === 1 ? matches[0]?.[0] : undefined;
    };
  };
  const boundaryRef = lookup(["boundary"]);
  const componentRef = lookup(["component"]);
  const layerRef = lookup(["boundary", "component"]);
  const controlRef = lookup(["control"]);
  const references = (
    record: TopologyRecord,
    field: string,
    resolve: ReturnType<typeof lookup>,
    idField = `${field}Ids`,
  ) => {
    const byId = Array.isArray(record[idField]);
    return strings(record[byId ? idField : field]).flatMap((value) => {
      const id = resolve(byId ? value : undefined, byId ? undefined : value);
      if (!id)
        warnings.push(
          `${surfaceText(record.name) || surfaceText(record.title) || record.id}: unresolved ${field} reference “${value}”.`,
        );
      return id ? [id] : [];
    });
  };
  const boundaries: Boundary[] = loaded.boundaries
    .map((record) => {
      const parent = boundaryRef(record.parentId, record.parent);
      if ((record.parentId || record.parent) && !parent)
        warnings.push(
          `${surfaceText(record.name) || record.id}: parent boundary is missing or ambiguous; shown at the top level.`,
        );
      return {
        id: `boundary:${record.id}`,
        name: surfaceText(record.name) || record.id,
        kind: oneOf(
          record.kind,
          [
            "edge-network",
            "cloud-account",
            "region",
            "vpc",
            "subnet",
            "third-party",
            "user-device",
            "unplaced",
          ],
          "unplaced",
        ),
        parent,
        provider: surfaceText(record.provider),
        description: surfaceText(record.description),
        evidence: evidence(record.evidence),
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id));
  const byId = new Map(boundaries.map((boundary) => [boundary.id, boundary]));
  // Persisted records can predate validation; break cycles before ELK traverses them.
  for (const boundary of boundaries) {
    const seen = new Set([boundary.id]);
    let parent = boundary.parent;
    while (parent) {
      if (seen.has(parent)) {
        boundary.parent = undefined;
        warnings.push(
          `${boundary.name}: cyclic parent reference; shown at the top level.`,
        );
        break;
      }
      seen.add(parent);
      parent = byId.get(parent)?.parent;
    }
  }
  const components: Component[] = loaded.components
    .map((record) => {
      const boundary = boundaryRef(record.boundaryId, record.boundary);
      if (!boundary)
        warnings.push(
          `${surfaceText(record.name) || record.id}: boundary is missing or ambiguous; shown under Unplaced.`,
        );
      return {
        id: `component:${record.id}`,
        recordId: record.id,
        name: surfaceText(record.name) || record.id,
        kind: oneOf(
          record.kind,
          [
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
          ],
          "compute",
        ),
        boundary: boundary ?? UNPLACED,
        tech: surfaceText(record.tech),
        exposure: oneOf(
          record.exposure,
          ["public", "private", "unknown"],
          "unknown",
        ),
        endpoints: strings(record.endpoints),
        usedBy: references(record, "usedBy", componentRef),
        repository: surfaceText(record.repository),
        description: surfaceText(record.description),
        atStake: surfaceText(record.atStake),
        trustAssumptions: strings(record.trustAssumptions),
        businessLogic: surfaceText(record.businessLogic),
        members: strings(record.members),
        evidence: evidence(record.evidence),
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id));
  if (components.some((component) => component.boundary === UNPLACED))
    boundaries.push({
      id: UNPLACED,
      name: "Unplaced",
      kind: "unplaced",
      evidence: [],
    });

  const flows = loaded.flows
    .flatMap((record) => {
      const from = componentRef(record.fromId, record.from);
      const to = componentRef(record.toId, record.to);
      if (!from || !to) {
        warnings.push(
          `${surfaceText(record.label) || record.id}: flow endpoint is missing or ambiguous; inspect it in Flows.`,
        );
        return [];
      }
      return [
        {
          id: `flow:${record.id}`,
          from,
          to,
          label: surfaceText(record.label),
          evidence: evidence(record.evidence),
        },
      ];
    })
    .sort((a, b) =>
      JSON.stringify([a.from, a.to, a.label]).localeCompare(
        JSON.stringify([b.from, b.to, b.label]),
      ),
    );
  const controls: Control[] = loaded.controls.map((record) => ({
    id: `control:${record.id}`,
    name: surfaceText(record.name) || record.id,
    kind: oneOf(
      record.kind,
      [
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
      ],
      "logging",
    ),
    appliesTo: references(record, "appliesTo", layerRef),
    protects: surfaceText(record.protects),
    gaps: surfaceText(record.gaps),
    evidence: evidence(record.evidence),
  }));
  const threats: Threat[] = loaded.threats.flatMap((record) => {
    const component = componentRef(record.componentId, record.component);
    if (!component) {
      warnings.push(
        `${surfaceText(record.title) || record.id}: threat component is missing or ambiguous; inspect it in Threats.`,
      );
      return [];
    }
    return [
      {
        id: `threat:${record.id}`,
        component,
        title: surfaceText(record.title) || record.id,
        category: oneOf(
          record.category,
          [
            "spoofing",
            "tampering",
            "repudiation",
            "information-disclosure",
            "denial-of-service",
            "elevation-of-privilege",
          ],
          "information-disclosure",
        ),
        entryPoint: surfaceText(record.entryPoint),
        scenario: surfaceText(record.scenario),
        attackSteps: strings(record.attackSteps),
        preconditions: strings(record.preconditions),
        impact: surfaceText(record.impact),
        severity: record.severity
          ? oneOf(record.severity, ["critical", "high", "medium", "low"], "low")
          : undefined,
        likelihood: oneOf(record.likelihood, ["low", "medium", "high"], "low"),
        likelihoodRationale: surfaceText(record.likelihoodRationale),
        controls: references(record, "controls", controlRef, "controlIds"),
        verification: surfaceText(record.verification),
        evidence: evidence(record.evidence),
      },
    ];
  });
  return {
    topology: {
      name: "Session attack surface",
      description: "",
      origin: "",
      boundaries,
      components,
      flows,
      controls,
      threats,
    },
    entries,
    warnings: [...new Set(warnings)],
  };
}
