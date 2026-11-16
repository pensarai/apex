/**
 * Renders a documented topology as a Mermaid flowchart: boundaries as nested
 * subgraphs, components as nodes shaped by kind, flows as labeled edges, and
 * optionally controls as dotted links to what they protect.
 *
 * Output is deterministic — sorted by name, with ids derived from names — so
 * two diagrams of the same system diff line by line. The records stay the
 * source of truth; this is a view of them.
 */

export interface MermaidTopology {
  boundaries: { name: string; kind: string; parent?: string }[];
  components: {
    name: string;
    kind: string;
    boundary: string;
    exposure?: string;
  }[];
  flows: { from: string; to: string; label?: string }[];
  controls?: { name: string; appliesTo: string[]; gaps?: string }[];
}

export interface MermaidOptions {
  /** Draw each control as a node with dotted links to what it applies to. */
  controls?: boolean;
}

const SHAPES: Record<string, [string, string]> = {
  database: ['[("', '")]'],
  cache: ['[("', '")]'],
  "object-store": ['[("', '")]'],
  queue: ['[["', '"]]'],
  "message-broker": ['[["', '"]]'],
  entrypoint: ['{{"', '"}}'],
  proxy: ['{{"', '"}}'],
  client: ['(["', '"])'],
  "identity-provider": ['("', '")'],
  "llm-provider": ['("', '")'],
  saas: ['("', '")'],
};

/** Mermaid labels are quoted; quotes and angle brackets must be entity codes. */
function label(text: string): string {
  return text
    .replace(/\s+/g, " ")
    .trim()
    .replace(/#/g, "#35;")
    .replace(/"/g, "#quot;")
    .replace(/</g, "#lt;")
    .replace(/>/g, "#gt;")
    .replace(/\|/g, "#124;");
}

const byName = <T extends { name: string }>(a: T, b: T) =>
  a.name.toLowerCase().localeCompare(b.name.toLowerCase());

/** Stable, collision-free ids: a slug of the name, numbered in sorted order when two collide. */
function idAllocator(prefix: string) {
  const ids = new Map<string, string>();
  const used = new Set<string>();
  return {
    assign(name: string): string {
      const key = name.toLowerCase();
      const existing = ids.get(key);
      if (existing) return existing;
      const base = `${prefix}_${key.replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "x"}`;
      let id = base;
      for (let n = 2; used.has(id); n++) id = `${base}_${n}`;
      used.add(id);
      ids.set(key, id);
      return id;
    },
    get: (name: string) => ids.get(name.toLowerCase()),
  };
}

export function topologyToMermaid(
  topology: MermaidTopology,
  options: MermaidOptions = {},
): string {
  const boundaries = [...topology.boundaries].sort(byName);
  const components = [...topology.components].sort(byName);
  const boundaryIds = idAllocator("b");
  const componentIds = idAllocator("c");
  for (const b of boundaries) boundaryIds.assign(b.name);
  for (const c of components) componentIds.assign(c.name);

  const lines = ["flowchart LR"];
  const known = new Set(boundaries.map((b) => b.name.toLowerCase()));
  const childBoundaries = (parent: string | undefined) =>
    boundaries.filter((b) =>
      parent === undefined
        ? !b.parent || !known.has(b.parent.toLowerCase())
        : b.parent?.toLowerCase() === parent.toLowerCase(),
    );
  const membersOf = (boundary: string | undefined) =>
    components.filter((c) =>
      boundary === undefined
        ? !known.has(c.boundary.toLowerCase())
        : c.boundary.toLowerCase() === boundary.toLowerCase(),
    );

  const node = (c: MermaidTopology["components"][number]) => {
    const [open, close] = SHAPES[c.kind] ?? ['["', '"]'];
    const id = componentIds.get(c.name) as string;
    const cls = c.exposure === "public" ? ":::public" : "";
    return `${id}${open}${label(`${c.name} (${c.kind})`)}${close}${cls}`;
  };

  const emit = (boundary: string | undefined, depth: number) => {
    const pad = "  ".repeat(depth);
    for (const c of membersOf(boundary)) lines.push(`${pad}${node(c)}`);
    for (const b of childBoundaries(boundary)) {
      lines.push(
        `${pad}subgraph ${boundaryIds.get(b.name)}["${label(`${b.name} (${b.kind})`)}"]`,
      );
      emit(b.name, depth + 1);
      lines.push(`${pad}end`);
    }
  };
  emit(undefined, 1);

  const missing = idAllocator("missing");
  const endpoint = (name: string) => {
    const id = componentIds.get(name);
    if (id) return id;
    const ghost = missing.get(name);
    if (ghost) return ghost;
    const created = missing.assign(name);
    lines.push(`  ${created}["${label(`${name} (undocumented)`)}"]:::missing`);
    return created;
  };

  const flows = new Map<string, MermaidTopology["flows"][number]>();
  for (const f of topology.flows)
    flows.set(
      `${f.from.toLowerCase()}\u0000${f.to.toLowerCase()}\u0000${(f.label ?? "").toLowerCase()}`,
      f,
    );
  const sortedFlows = [...flows.values()].sort(
    (a, b) =>
      a.from.toLowerCase().localeCompare(b.from.toLowerCase()) ||
      a.to.toLowerCase().localeCompare(b.to.toLowerCase()) ||
      (a.label ?? "").localeCompare(b.label ?? ""),
  );
  for (const f of sortedFlows) {
    const from = endpoint(f.from);
    const to = endpoint(f.to);
    lines.push(
      f.label?.trim()
        ? `  ${from} -->|"${label(f.label)}"| ${to}`
        : `  ${from} --> ${to}`,
    );
  }

  if (options.controls) {
    const controlIds = idAllocator("ctl");
    for (const ctl of [...(topology.controls ?? [])].sort(byName)) {
      const id = controlIds.assign(ctl.name);
      lines.push(
        `  ${id}>"${label(ctl.name)}"]${ctl.gaps?.trim() ? ":::gap" : ""}`,
      );
      for (const target of [...ctl.appliesTo].sort()) {
        const to =
          componentIds.get(target) ??
          boundaryIds.get(target) ??
          endpoint(target);
        lines.push(`  ${id} -.-> ${to}`);
      }
    }
  }

  lines.push(
    "  classDef public stroke-width:2px",
    "  classDef missing stroke-dasharray:4 3",
    "  classDef gap stroke-dasharray:2 2",
  );
  return `${lines.join("\n")}\n`;
}
