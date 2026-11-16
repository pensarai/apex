import { describe, expect, it } from "vitest";
import type { LoadedTopology } from "../../../src/core/agents/offSecAgent/tools/topologyRecords";
import {
  surfaceEntries,
  surfaceKey,
  surfaceLabel,
} from "./attack-surface-model";

const topology = (patch: Partial<LoadedTopology> = {}): LoadedTopology => ({
  boundaries: [],
  components: [],
  flows: [],
  controls: [],
  threats: [],
  retired: [],
  ...patch,
});

describe("session attack surface inventory", () => {
  it("nests boundaries and components by stable IDs despite duplicate names", () => {
    const rows = surfaceEntries(
      topology({
        boundaries: [
          { id: "account", name: "Production" },
          {
            id: "private",
            name: "Private subnet",
            parentId: "account",
            parent: "Old account name",
          },
          { id: "other", name: "Production" },
        ],
        components: [
          {
            id: "db",
            name: "Postgres",
            boundaryId: "private",
            boundary: "Old subnet name",
          },
        ],
      }),
      "map",
    );
    expect(rows.map((row) => [row.record.id, row.depth])).toEqual([
      ["account", 0],
      ["private", 1],
      ["db", 2],
      ["other", 0],
    ]);
  });

  it("keeps records with missing references inspectable and does not reattach a stale ID by name", () => {
    const rows = surfaceEntries(
      topology({
        boundaries: [
          { id: "cloud", name: "Cloud" },
          {
            id: "orphan",
            name: "Orphan",
            parentId: "missing",
            parent: "Cloud",
          },
        ],
        components: [
          { id: "api", name: "API", boundaryId: "missing", boundary: "Cloud" },
        ],
      }),
      "map",
    );
    expect(
      rows
        .filter((row) => row.detached)
        .map((row) => [row.record.id, row.depth]),
    ).toEqual([
      ["orphan", 0],
      ["api", 0],
    ]);
  });

  it("includes cyclic and self-parented boundaries once without hiding their components", () => {
    const rows = surfaceEntries(
      topology({
        boundaries: [
          { id: "a", name: "A", parentId: "b" },
          { id: "b", name: "B", parentId: "a" },
          { id: "c", name: "C", parentId: "c" },
        ],
        components: [{ id: "worker", name: "Worker", boundaryId: "b" }],
      }),
      "map",
    );
    expect(rows.map((row) => row.record.id).sort()).toEqual([
      "a",
      "b",
      "c",
      "worker",
    ]);
    expect(
      rows.filter((row) => row.detached).map((row) => row.record.id),
    ).toEqual(["a", "c"]);
  });

  it("supports case-insensitive boundary names in legacy sessions", () => {
    const rows = surfaceEntries(
      topology({
        boundaries: [
          { id: "cloud", name: "Cloud" },
          { id: "vpc", name: "VPC", parent: "CLOUD" },
        ],
        components: [{ id: "api", name: "API", boundary: "vpc" }],
      }),
      "map",
    );
    expect(rows.map((row) => [row.record.id, row.depth])).toEqual([
      ["cloud", 0],
      ["vpc", 1],
      ["api", 2],
    ]);
  });

  it("keeps retired records outside the active topology and resolves flow directions", () => {
    const data = topology({
      flows: [{ id: "https", from: "Browser", to: "API", label: "HTTPS" }],
      retired: [
        { kind: "component", record: { id: "old", name: "Legacy API" } },
      ],
    });
    expect(surfaceEntries(data, "map")).toEqual([]);
    expect(surfaceLabel(surfaceEntries(data, "flows")[0])).toBe(
      "Browser → API",
    );
    expect(surfaceKey(surfaceEntries(data, "retired")[0])).toBe(
      "retired:component:old",
    );
  });

  it("keeps selection identity stable when a record is renamed", () => {
    const before = surfaceEntries(
      topology({ components: [{ id: "api", name: "Old" }] }),
      "map",
    )[0];
    const after = surfaceEntries(
      topology({ components: [{ id: "api", name: "New" }] }),
      "map",
    )[0];
    expect(surfaceKey(before)).toBe(surfaceKey(after));
    expect(surfaceLabel(after)).toBe("New");
  });
});
