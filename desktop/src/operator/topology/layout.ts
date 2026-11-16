// Ported from Console attack-surface/topology/layout.ts at 921b7c871; keep selection and layout aligned.
import type ELK from "elkjs/lib/elk.bundled.js";
import type { ElkExtendedEdge, ElkNode } from "elkjs/lib/elk.bundled.js";
import { INTERNET, publicEntrypoints } from "./graph";
import type {
  Component,
  Evidence,
  EvidenceSource,
  Flow,
  Topology,
} from "./types";

let elkInstance: Promise<InstanceType<typeof ELK>> | null = null;
function elk(): Promise<InstanceType<typeof ELK>> {
  elkInstance ??= import("elkjs/lib/elk.bundled.js")
    .then(({ default: ELK }) => new ELK())
    .catch((error: unknown) => {
      elkInstance = null;
      throw error;
    });
  return elkInstance;
}

export const COMPONENT_W = 210;
export const COMPONENT_H = 62;

const EVIDENCE_RANK: EvidenceSource[] = [
  "observed",
  "cloud",
  "source",
  "inferred",
];
export function strongest(evidence: Evidence[]): EvidenceSource {
  for (const source of EVIDENCE_RANK)
    if (evidence.some((e) => e.source === source)) return source;
  return "inferred";
}

export type TopologySelection =
  | { type: "component" | "boundary" | "control"; id: string }
  | { type: "route"; id: string; route: EdgeNetworkRoute }
  | null;

export const EXPECTS_CONTROLS = new Set<Component["kind"]>([
  "application",
  "entrypoint",
  "database",
  "cache",
  "object-store",
  "queue",
]);

const KIND_ORDER: Component["kind"][] = [
  "client",
  "entrypoint",
  "application",
  "compute",
  "proxy",
  "database",
  "cache",
  "queue",
  "object-store",
  "message-broker",
  "llm-provider",
  "identity-provider",
  "saas",
];

export interface Positioned {
  x: number;
  y: number;
  width: number;
  height: number;
  parent?: string;
}

export function absoluteBox(positions: Map<string, Positioned>, id: string) {
  const node = positions.get(id);
  if (!node) throw new Error(`Missing layout position for ${id}`);
  let { x, y } = node;
  let parent = node.parent;
  while (parent) {
    const box = positions.get(parent);
    if (!box) throw new Error(`Missing parent layout position for ${parent}`);
    x += box.x;
    y += box.y;
    parent = box.parent;
  }
  return { x, y, width: node.width, height: node.height };
}

export function facingHandles(
  positions: Map<string, Positioned>,
  source: string,
  target: string,
) {
  if (!positions.has(source) || !positions.has(target)) return {};
  const a = absoluteBox(positions, source);
  const b = absoluteBox(positions, target);
  const dx = b.x + b.width / 2 - (a.x + a.width / 2);
  const dy = b.y + b.height / 2 - (a.y + a.height / 2);
  const [out, into] =
    Math.abs(dx) >= Math.abs(dy)
      ? dx >= 0
        ? ["right", "left"]
        : ["left", "right"]
      : dy >= 0
        ? ["bottom", "top"]
        : ["top", "bottom"];
  return { sourceHandle: `out-${out}`, targetHandle: `in-${into}` };
}

export interface EdgeNetworkRoute {
  id: string;
  source: string;
  target: string;
  flows: Flow[];
}

export function edgeNetworkRoutes(topology: Topology) {
  const boundaries = new Map(topology.boundaries.map((b) => [b.id, b]));
  const paths = new Map(
    topology.components.map((c) => {
      const path = [c.id];
      let boundary = boundaries.get(c.boundary);
      while (boundary) {
        path.unshift(boundary.id);
        boundary = boundary.parent
          ? boundaries.get(boundary.parent)
          : undefined;
      }
      return [c.id, path] as const;
    }),
  );
  const routes = new Map<string, EdgeNetworkRoute>();
  for (const flow of topology.flows) {
    const from = paths.get(flow.from);
    const to = paths.get(flow.to);
    if (!from || !to)
      throw new Error("Cannot route a flow with an undocumented endpoint");
    if (
      !from.some(
        (id) => boundaries.get(id)?.kind === "edge-network" && !to.includes(id),
      )
    )
      continue;
    let split = 0;
    while (from[split] === to[split]) split++;
    const source = from[split];
    const target = to[split];
    const id = JSON.stringify([source, target]);
    const route = routes.get(id);
    if (route) route.flows.push(flow);
    else routes.set(id, { id, source, target, flows: [flow] });
  }
  return routes;
}

export async function layoutTopology(
  topology: Topology,
  routes = edgeNetworkRoutes(topology),
) {
  const childrenOf = (parent: string | undefined): ElkNode[] => [
    ...topology.components
      .filter((c) => c.boundary === parent)
      .sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind))
      .map((c) => ({ id: c.id, width: COMPONENT_W, height: COMPONENT_H })),
    ...topology.boundaries
      .filter((b) => b.parent === parent)
      .map((b) => ({
        id: b.id,
        layoutOptions: {
          "elk.algorithm": "rectpacking",
          "elk.aspectRatio": "1.6",
          "elk.spacing.nodeNode": "18",
          "elk.padding": "[top=40,left=16,bottom=16,right=16]",
        },
        children: childrenOf(b.id),
      })),
  ];
  const componentById = new Map(topology.components.map((c) => [c.id, c]));
  const boundaryById = new Map(topology.boundaries.map((b) => [b.id, b]));
  const topLevel = (id: string): string => {
    if (id === INTERNET) return id;
    let boundary = boundaryById.get(componentById.get(id)?.boundary ?? "");
    while (boundary?.parent) boundary = boundaryById.get(boundary.parent);
    return boundary?.id ?? id;
  };
  const links = new Map<string, ElkExtendedEdge>();
  const link = (from: string, to: string) => {
    const id = JSON.stringify([from, to]);
    links.set(id, { id, sources: [from], targets: [to] });
  };
  for (const c of publicEntrypoints(topology)) link(INTERNET, topLevel(c.id));
  for (const f of topology.flows) {
    const from = topLevel(f.from);
    const to = topLevel(f.to);
    if (from !== to && to !== INTERNET) link(from, to);
  }
  const graph = await (await elk()).layout({
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "RIGHT",
      "elk.edgeRouting": "ORTHOGONAL",
      "elk.layered.spacing.nodeNodeBetweenLayers": "80",
      "elk.spacing.nodeNode": "40",
    },
    children: [
      { id: INTERNET, width: 120, height: COMPONENT_H },
      ...childrenOf(undefined),
    ],
    edges: [...links.values()],
  });
  const out = new Map<string, Positioned>();
  const walk = (node: ElkNode, parent?: string) => {
    for (const child of node.children ?? []) {
      out.set(child.id, {
        x: child.x ?? 0,
        y: child.y ?? 0,
        width: child.width ?? COMPONENT_W,
        height: child.height ?? COMPONENT_H,
        parent,
      });
      walk(child, child.id);
    }
  };
  walk(graph);
  // ELK routes between outer boxes, so an overview line can stop at a boundary
  // without cutting through unrelated components on the way to an entry point.
  const overview = (graph.edges ?? [])
    .filter((edge) => edge.sources[0] === INTERNET || routes.has(edge.id))
    .map((edge) => {
      if (!edge.sections?.length)
        throw new Error(`Missing ELK overview route for ${edge.id}`);
      return {
        id: edge.id,
        source: edge.sources[0],
        target: edge.targets[0],
        path: edge.sections
          .map((section) => {
            const points = [
              section.startPoint,
              ...(section.bendPoints ?? []),
              section.endPoint,
            ];
            return points
              .map((p, i) => `${i ? "L" : "M"} ${p.x} ${p.y}`)
              .join(" ");
          })
          .join(" "),
      };
    });
  // Inside one outer boundary ELK packs boxes without routing. Connect the
  // diverging children with React Flow's step path in that case.
  const routed = new Set(overview.map((edge) => edge.id));
  const nested = [...routes.values()]
    .filter((r) => !routed.has(r.id))
    .map(({ id, source, target }) => ({ id, source, target, path: null }));
  return { positions: out, overview: [...overview, ...nested] };
}

export function componentsWithin(
  topology: Topology,
  boundaryId: string,
): Set<string> {
  const ids = new Set<string>([boundaryId]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const b of topology.boundaries)
      if (b.parent && ids.has(b.parent) && !ids.has(b.id)) {
        ids.add(b.id);
        grew = true;
      }
  }
  return new Set(
    topology.components.filter((c) => ids.has(c.boundary)).map((c) => c.id),
  );
}

export function activeSet(
  topology: Topology,
  selection: TopologySelection,
): Set<string> | null {
  if (!selection) return null;
  if (selection.type === "route")
    return new Set(selection.route.flows.flatMap((f) => [f.from, f.to]));
  const withInternet = (ids: Set<string>) => {
    if (publicEntrypoints(topology).some((c) => ids.has(c.id)))
      ids.add(INTERNET);
    return ids;
  };
  if (selection.type === "boundary") {
    const inside = componentsWithin(topology, selection.id);
    const active = withInternet(new Set(inside));
    if (
      topology.boundaries.find((b) => b.id === selection.id)?.kind ===
      "edge-network"
    )
      for (const flow of topology.flows)
        if (inside.has(flow.from)) active.add(flow.to);
    return active;
  }
  if (selection.type === "control") {
    const layers = topology.controls.find(
      (c) => c.id === selection.id,
    )?.appliesTo;
    if (!layers) return null;
    return withInternet(
      new Set(layers.flatMap((id) => [id, ...componentsWithin(topology, id)])),
    );
  }
  const component = topology.components.find((c) => c.id === selection.id);
  if (!component) return null;
  const ids = new Set([component.id]);
  if (component.kind === "application") {
    for (const c of topology.components)
      if (c.usedBy.includes(component.id)) ids.add(c.id);
  }
  for (const f of topology.flows) {
    if (f.from === component.id) ids.add(f.to);
    if (f.to === component.id) ids.add(f.from);
  }
  if (component.kind === "entrypoint" && component.exposure === "public")
    ids.add(INTERNET);
  return ids;
}

export function focusedFlows(
  topology: Topology,
  selection: TopologySelection,
  active: Set<string> | null,
) {
  if (!selection || !active) return [];
  if (selection.type === "route") return selection.route.flows;
  if (
    selection.type === "boundary" &&
    topology.boundaries.find((b) => b.id === selection.id)?.kind ===
      "edge-network"
  ) {
    const inside = componentsWithin(topology, selection.id);
    return topology.flows.filter((f) => inside.has(f.from));
  }
  return topology.flows.filter((flow) =>
    selection.type === "component"
      ? flow.from === selection.id || flow.to === selection.id
      : active.has(flow.from) && active.has(flow.to),
  );
}

export function structureKey(topology: Topology): string {
  return JSON.stringify([
    topology.boundaries.map((b) => [b.id, b.parent, b.kind]),
    topology.components.map((c) => [c.id, c.boundary, c.kind, c.exposure]),
    topology.flows.map((f) => [f.from, f.to]),
  ]);
}

export function parseSelection(
  value: string,
  topology: Topology,
  routes = edgeNetworkRoutes(topology),
): TopologySelection {
  const [type, ...rest] = value.split(":");
  const id = rest.join(":");
  if (type === "route") {
    const route = routes.get(id);
    return route ? { type, id, route } : null;
  }
  if (type === "component" && topology.components.some((c) => c.id === id))
    return { type, id };
  if (type === "boundary" && topology.boundaries.some((b) => b.id === id))
    return { type, id };
  if (type === "control" && topology.controls.some((c) => c.id === id))
    return { type, id };
  return null;
}
