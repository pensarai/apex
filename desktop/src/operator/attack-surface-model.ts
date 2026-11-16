import type {
  LoadedTopology,
  RecordKind,
  TopologyRecord,
} from "../../../src/core/agents/offSecAgent/tools/topologyRecords";

export type SurfaceTab = "map" | "flows" | "controls" | "threats" | "retired";
export interface SurfaceEntry {
  kind: RecordKind;
  record: TopologyRecord;
  depth: number;
  detached?: boolean;
  retired?: boolean;
}

export function surfaceText(value: unknown): string {
  return typeof value === "string" ? value : "";
}

export function surfaceLabel(entry: SurfaceEntry): string {
  const record = entry.record;
  if (entry.kind === "flow")
    return `${surfaceText(record.from) || "Unknown source"} → ${surfaceText(record.to) || "Unknown destination"}`;
  return surfaceText(record.name) || surfaceText(record.title) || record.id;
}

export function surfaceKey(entry: SurfaceEntry): string {
  return `${entry.retired ? "retired:" : ""}${entry.kind}:${entry.record.id}`;
}

export function surfaceEntries(
  topology: LoadedTopology,
  tab: SurfaceTab,
): SurfaceEntry[] {
  if (tab === "retired")
    return topology.retired.map(({ kind, record }) => ({
      kind,
      record,
      depth: 0,
      retired: true,
    }));
  if (tab !== "map") {
    const kind = { flows: "flow", controls: "control", threats: "threat" }[
      tab
    ] as RecordKind;
    return topology[tab].map((record) => ({ kind, record, depth: 0 }));
  }
  const boundaries = [...topology.boundaries].sort((a, b) =>
    surfaceText(a.name).localeCompare(surfaceText(b.name)),
  );
  const byId = new Map(boundaries.map((record) => [record.id, record]));
  const byName = new Map(
    boundaries.map((record) => [
      surfaceText(record.name).toLowerCase(),
      record,
    ]),
  );
  const parentFor = (record: TopologyRecord, field: "parent" | "boundary") => {
    const id = surfaceText(record[`${field}Id`]);
    return id
      ? byId.get(id)
      : byName.get(surfaceText(record[field]).toLowerCase());
  };
  const children = new Map<string, TopologyRecord[]>();
  const components = new Map<string, TopologyRecord[]>();
  const roots: TopologyRecord[] = [];
  const unplaced: TopologyRecord[] = [];
  for (const record of boundaries) {
    const parent = parentFor(record, "parent");
    if (parent)
      children.set(parent.id, [...(children.get(parent.id) ?? []), record]);
    else roots.push(record);
  }
  for (const record of [...topology.components].sort((a, b) =>
    surfaceText(a.name).localeCompare(surfaceText(b.name)),
  )) {
    const boundary = parentFor(record, "boundary");
    if (boundary)
      components.set(boundary.id, [
        ...(components.get(boundary.id) ?? []),
        record,
      ]);
    else unplaced.push(record);
  }
  const entries: SurfaceEntry[] = [];
  const visited = new Set<string>();
  const visit = (root: TopologyRecord, detached: boolean) => {
    const stack: SurfaceEntry[] = [
      { kind: "boundary", record: root, depth: 0, detached },
    ];
    while (stack.length) {
      const entry = stack.pop();
      if (!entry || visited.has(surfaceKey(entry))) continue;
      visited.add(surfaceKey(entry));
      entries.push(entry);
      if (entry.kind !== "boundary") continue;
      const nested: SurfaceEntry[] = [
        ...(children.get(entry.record.id) ?? []).map((record) => ({
          kind: "boundary" as const,
          record,
          depth: entry.depth + 1,
        })),
        ...(components.get(entry.record.id) ?? []).map((record) => ({
          kind: "component" as const,
          record,
          depth: entry.depth + 1,
        })),
      ];
      stack.push(...nested.reverse());
    }
  };
  for (const root of roots) visit(root, Boolean(root.parentId || root.parent));
  // Historical records can contain cycles; keep every record inspectable once.
  for (const record of boundaries)
    if (!visited.has(`boundary:${record.id}`)) visit(record, true);
  entries.push(
    ...unplaced.map((record) => ({
      kind: "component" as const,
      record,
      depth: 0,
      detached: true,
    })),
  );
  return entries;
}
