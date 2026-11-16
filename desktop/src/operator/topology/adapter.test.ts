import { describe, expect, it } from "vitest";
import type { LoadedTopology } from "../../../../src/core/agents/offSecAgent/tools/topologyRecords";
import { adaptSessionTopology } from "./adapter";
import { layoutTopology, structureKey } from "./layout";

const empty = (): LoadedTopology => ({
  boundaries: [],
  components: [],
  flows: [],
  controls: [],
  threats: [],
  retired: [],
});
const fixture = (): LoadedTopology => ({
  ...empty(),
  boundaries: [
    { id: "b1", name: "Cloud", kind: "cloud-account" },
    {
      id: "b2",
      name: "Private",
      kind: "subnet",
      parentId: "b1",
      parent: "Old cloud name",
    },
  ],
  components: [
    {
      id: "c1",
      name: "Gateway",
      kind: "entrypoint",
      exposure: "public",
      boundaryId: "b1",
      evidence: [{ source: "observed", detail: "HTTPS responds" }],
    },
    {
      id: "c2",
      name: "API",
      kind: "application",
      boundaryId: "b2",
      usedByIds: ["c1"],
    },
  ],
  flows: [
    {
      id: "f1",
      fromId: "c1",
      from: "Old gateway name",
      toId: "c2",
      to: "Old API name",
      label: "HTTPS",
    },
  ],
  controls: [
    {
      id: "a1",
      name: "Auth",
      kind: "authentication",
      appliesToIds: ["c2", "b2"],
    },
  ],
  threats: [
    {
      id: "t1",
      title: "Cross tenant access",
      componentId: "c2",
      controlIds: ["a1"],
      controls: ["Old auth name"],
    },
  ],
});

describe("session topology adapter", () => {
  it("links stable IDs through renames and retains original records for the inspector", () => {
    const loaded = fixture();
    const { topology, entries, warnings } = adaptSessionTopology(loaded);
    expect(warnings).toEqual([]);
    expect(topology.boundaries[1]?.parent).toBe("boundary:b1");
    expect(topology.components[1]?.boundary).toBe("boundary:b2");
    expect(topology.components[1]?.usedBy).toEqual(["component:c1"]);
    expect(topology.flows[0]).toMatchObject({
      id: "flow:f1",
      from: "component:c1",
      to: "component:c2",
    });
    expect(topology.controls[0]?.appliesTo).toEqual([
      "component:c2",
      "boundary:b2",
    ]);
    expect(topology.threats[0]).toMatchObject({
      component: "component:c2",
      controls: ["control:a1"],
    });
    expect(entries.get("component:c1")?.record).toBe(loaded.components[0]);
  });

  it("supports unambiguous legacy names but never redirects a missing explicit ID", () => {
    const loaded = fixture();
    loaded.components.push({
      id: "legacy",
      name: "Worker",
      boundary: "private",
      usedBy: ["Gateway"],
    });
    loaded.flows.push({ id: "legacy-flow", from: "Worker", to: "API" });
    loaded.flows.push({
      id: "broken-flow",
      fromId: "removed",
      from: "Gateway",
      toId: "c2",
    });
    loaded.threats.push({
      id: "legacy-threat",
      component: "Worker",
      controls: ["Auth"],
    });
    const result = adaptSessionTopology(loaded);
    expect(
      result.topology.components.find((c) => c.id === "component:legacy"),
    ).toMatchObject({ boundary: "boundary:b2", usedBy: ["component:c1"] });
    expect(result.topology.flows).toHaveLength(2);
    expect(
      result.topology.flows.find((f) => f.id === "flow:legacy-flow"),
    ).toMatchObject({ from: "component:legacy", to: "component:c2" });
    expect(result.topology.threats[1]?.controls).toEqual(["control:a1"]);
    expect(result.warnings).toEqual([expect.stringContaining("broken-flow")]);
    expect(result.entries.has("flow:broken-flow")).toBe(true);
  });

  it("keeps ambiguous names and retired endpoints out of active edges", () => {
    const loaded = fixture();
    loaded.components.push({ id: "duplicate", name: "API", boundaryId: "b2" });
    loaded.retired.push({
      kind: "component",
      record: { id: "old", name: "Retired API" },
    });
    loaded.flows.push(
      { id: "ambiguous", from: "Gateway", to: "API" },
      { id: "retired", fromId: "c1", toId: "old" },
    );
    const result = adaptSessionTopology(loaded);
    expect(result.topology.flows).toHaveLength(1);
    expect(result.entries.has("component:old")).toBe(false);
    expect(result.warnings).toHaveLength(2);
  });

  it("makes cycles and orphans layout-safe without losing inspectable records", async () => {
    const loaded = fixture();
    loaded.boundaries = loaded.boundaries.map((boundary, i) =>
      i === 0 ? { ...boundary, parentId: "b2" } : boundary,
    );
    loaded.boundaries.push({
      id: "orphan",
      name: "Orphan",
      parentId: "absent",
    });
    loaded.components.push({
      id: "unplaced",
      name: "Worker",
      boundaryId: "absent",
    });
    const { topology, entries, warnings } = adaptSessionTopology(loaded);
    const layout = await layoutTopology(topology);
    expect(layout.positions.size).toBe(8);
    expect(
      topology.components.find((c) => c.id === "component:unplaced")?.boundary,
    ).toBe("__unplaced");
    expect(warnings).toHaveLength(3);
    for (const id of [
      "boundary:b1",
      "boundary:b2",
      "boundary:orphan",
      "component:unplaced",
    ])
      expect(entries.has(id) && layout.positions.has(id)).toBe(true);
  });

  it("keeps the layout key stable across record refreshes, reordering, and renames", () => {
    const loaded = fixture();
    const before = structureKey(adaptSessionTopology(loaded).topology);
    loaded.boundaries.reverse();
    loaded.components.reverse();
    loaded.components = loaded.components.map((component, i) =>
      i === 0
        ? { ...component, name: "Renamed API", description: "Updated evidence" }
        : component,
    );
    expect(structureKey(adaptSessionTopology(loaded).topology)).toBe(before);
    loaded.flows.push({ id: "reverse", fromId: "c2", toId: "c1" });
    expect(structureKey(adaptSessionTopology(loaded).topology)).not.toBe(
      before,
    );
  });
});
