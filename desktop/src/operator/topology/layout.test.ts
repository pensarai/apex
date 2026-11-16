import { describe, expect, it } from "vitest";
import {
  activeSet,
  edgeNetworkRoutes,
  facingHandles,
  focusedFlows,
  layoutTopology,
  parseSelection,
  strongest,
  structureKey,
} from "./layout";
import type { Topology } from "./types";

const component = (
  id: string,
  boundary: string,
  fields: Record<string, unknown> = {},
) => ({
  id,
  name: id,
  kind: "compute",
  boundary,
  exposure: "private",
  usedBy: [],
  atStake: "",
  trustAssumptions: [],
  evidence: [],
  ...fields,
});

const topology = {
  name: "System map",
  description: "",
  origin: "",
  boundaries: [
    { id: "aws", name: "AWS", kind: "cloud-account", evidence: [] },
    {
      id: "priv",
      name: "Private",
      kind: "subnet",
      parent: "aws",
      evidence: [],
    },
  ],
  components: [
    component("cmp:cdn", "aws", { kind: "entrypoint", exposure: "public" }),
    component("cmp:api", "priv", { kind: "application" }),
    component("cmp:db", "priv", { kind: "database", usedBy: ["cmp:api"] }),
    component("cmp:queue", "priv", { kind: "queue" }),
  ],
  flows: [
    { from: "cmp:cdn", to: "cmp:api", label: "HTTPS", evidence: [] },
    { from: "cmp:api", to: "cmp:queue", label: "SQS", evidence: [] },
  ],
  controls: [
    {
      id: "ctl:waf",
      name: "WAF",
      kind: "waf",
      appliesTo: ["cmp:cdn"],
      protects: "",
      evidence: [],
    },
  ],
  threats: [],
} as unknown as Topology;

describe("activeSet", () => {
  it("lights an application, its flow neighbors, and its documented dependencies", () => {
    expect(activeSet(topology, { type: "component", id: "cmp:api" })).toEqual(
      new Set(["cmp:api", "cmp:db", "cmp:cdn", "cmp:queue"]),
    );
  });

  it("lights a component's flow neighbors, a boundary's contents at any depth, and a control's layers", () => {
    expect(activeSet(topology, { type: "component", id: "cmp:queue" })).toEqual(
      new Set(["cmp:queue", "cmp:api"]),
    );
    expect(activeSet(topology, { type: "boundary", id: "aws" })).toEqual(
      new Set(["cmp:cdn", "cmp:api", "cmp:db", "cmp:queue", "__internet"]),
    );
    expect(activeSet(topology, { type: "control", id: "ctl:waf" })).toEqual(
      new Set(["cmp:cdn", "__internet"]),
    );
    expect(activeSet(topology, null)).toBeNull();
  });
});

describe("structureKey and strongest", () => {
  it("changes with the graph shape but not with a reworded record", () => {
    const reworded = {
      ...topology,
      components: topology.components.map((c) => ({
        ...c,
        atStake: "changed",
      })),
    };
    expect(structureKey(reworded)).toBe(structureKey(topology));
    expect(structureKey({ ...topology, flows: [] })).not.toBe(
      structureKey(topology),
    );
  });

  it("ranks seen live over cloud over source over inferred", () => {
    expect(
      strongest([
        { source: "source", detail: "" },
        { source: "cloud", detail: "" },
      ]),
    ).toBe("cloud");
    expect(strongest([])).toBe("inferred");
  });
});

describe("overview and focused connections", () => {
  it("routes one ingress line per outer boundary, even across nested entry points", async () => {
    const entry = topology.components[0];
    const { overview } = await layoutTopology({
      ...topology,
      boundaries: [
        ...topology.boundaries,
        { ...topology.boundaries[0], id: "external|provider" },
      ],
      components: [
        ...topology.components,
        { ...entry, id: "nested", boundary: "priv" },
        { ...entry, id: "external-entry", boundary: "external|provider" },
        { ...entry, id: "private-entry", exposure: "private" },
      ],
    });
    expect(overview.map((e) => e.target).sort()).toEqual([
      "aws",
      "external|provider",
    ]);
    for (const edge of overview) {
      expect(edge.source).toBe("__internet");
      expect(edge.path).toMatch(/^M .+L /);
    }
  });

  it("shows only incident flows on a component, even if two neighbors are connected", () => {
    const neighborFlow = {
      ...topology.flows[0],
      from: "cmp:queue",
      to: "cmp:db",
    };
    const map = { ...topology, flows: [...topology.flows, neighborFlow] };
    const app = { type: "component", id: "cmp:api" } as const;
    expect(focusedFlows(map, app, activeSet(map, app))).toEqual(topology.flows);
    const boundary = { type: "boundary", id: "priv" } as const;
    expect(focusedFlows(map, boundary, activeSet(map, boundary))).toEqual([
      topology.flows[1],
      neighborFlow,
    ]);
    expect(focusedFlows(map, null, null)).toEqual([]);
  });
});

describe("edge-network connections", () => {
  const edges = {
    ...topology,
    boundaries: [
      ...topology.boundaries,
      { ...topology.boundaries[0], id: "edge", kind: "edge-network" as const },
      { ...topology.boundaries[0], id: "pop", parent: "edge" },
    ],
    components: [
      ...topology.components,
      { ...topology.components[0], id: "worker", boundary: "pop" },
    ],
    flows: [
      ...topology.flows,
      { from: "worker", to: "cmp:cdn", label: "forward", evidence: [] },
      { from: "worker", to: "cmp:api", label: "stream", evidence: [] },
      {
        from: "cmp:api",
        to: "worker",
        label: "outbound request",
        evidence: [],
      },
    ],
  };

  it("draws one directed arrow for the documented handoffs and expands just those flows", async () => {
    const routes = edgeNetworkRoutes(edges);
    const [route] = routes.values();
    expect(routes.size).toBe(1);
    expect(route).toMatchObject({
      source: "edge",
      target: "aws",
      flows: edges.flows.slice(2, 4),
    });
    const { overview } = await layoutTopology(edges);
    expect(overview.filter((e) => e.source !== "__internet")).toEqual([
      expect.objectContaining({
        id: route.id,
        source: "edge",
        target: "aws",
        path: expect.stringMatching(/^M /),
      }),
    ]);
    const selection = { type: "route", id: route.id, route } as const;
    expect(activeSet(edges, selection)).toEqual(
      new Set(["worker", "cmp:cdn", "cmp:api"]),
    );
    expect(focusedFlows(edges, selection, activeSet(edges, selection))).toEqual(
      route.flows,
    );
    const boundary = { type: "boundary", id: "edge" } as const;
    expect(focusedFlows(edges, boundary, activeSet(edges, boundary))).toEqual(
      route.flows,
    );
  });

  it("connects nested sibling boundaries inside one account without a self-loop", async () => {
    const nested = {
      ...edges,
      boundaries: edges.boundaries.map((b) =>
        b.id === "edge" ? { ...b, parent: "aws" } : b,
      ),
    };
    const { overview } = await layoutTopology(nested);
    expect(
      overview
        .filter((e) => e.source === "edge")
        .map((e) => e.target)
        .sort(),
    ).toEqual(["cmp:cdn", "priv"]);
  });

  it("chooses the facing sides using absolute positions in nested boxes", () => {
    const box = { x: 0, y: 0, width: 210, height: 62 };
    const positions = new Map([
      ["source", { ...box, parent: "outer" }],
      ["outer", { ...box, x: 1000 }],
      ["left", { ...box, x: 20 }],
      ["below", { ...box, x: 1000, y: 450 }],
    ]);
    expect(facingHandles(positions, "source", "left")).toEqual({
      sourceHandle: "out-left",
      targetHandle: "in-right",
    });
    expect(facingHandles(positions, "source", "below")).toEqual({
      sourceHandle: "out-bottom",
      targetHandle: "in-top",
    });
  });
});
describe("parseSelection", () => {
  it("reads kind:id from the URL, ids with colons included, and ignores anything not in the map", () => {
    expect(parseSelection("component:cmp:api", topology)).toEqual({
      type: "component",
      id: "cmp:api",
    });
    expect(parseSelection("boundary:priv", topology)).toEqual({
      type: "boundary",
      id: "priv",
    });
    expect(parseSelection("component:cmp:gone", topology)).toBeNull();
    expect(parseSelection("nonsense", topology)).toBeNull();
  });
});
