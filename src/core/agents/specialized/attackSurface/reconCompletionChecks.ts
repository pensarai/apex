import { createHash } from "node:crypto";
import { z } from "zod";
import { withHttpScheme } from "../../../../util/url";
import { loadTopology } from "../../offSecAgent/tools/topologyRecords";

export function completionSnapshot(root: string, report: unknown): string {
  const topology = Object.fromEntries(
    Object.entries(loadTopology(root)).map(([kind, records]) => [
      kind,
      [...records].sort((a, b) => String(a.id).localeCompare(String(b.id))),
    ]),
  );
  const canonical = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === "object")
      return Object.fromEntries(
        Object.entries(value)
          .filter(([key]) => !["recordedAt", "sessionId"].includes(key))
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, item]) => [key, canonical(item)]),
      );
    return value;
  };
  return createHash("sha256")
    .update(JSON.stringify(canonical({ topology, report })))
    .digest("hex");
}

export function structuralGaps(root: string): string[] {
  const topology = loadTopology(root);
  const records = [
    ...topology.boundaries,
    ...topology.components,
    ...topology.flows,
    ...topology.controls,
    ...topology.threats,
  ];
  const ids = new Set(records.map((r) => r.id));
  const gaps: string[] = [];
  for (const record of records) {
    for (const key of [
      "parentId",
      "boundaryId",
      "fromId",
      "toId",
      "componentId",
      "usedByIds",
      "appliesToIds",
      "controlIds",
    ]) {
      const value = record[key];
      const refs = Array.isArray(value) ? value : value ? [value] : [];
      for (const ref of refs)
        if (!ids.has(String(ref)))
          gaps.push(
            `${record.id}: ${key} references missing or retired record ${ref}`,
          );
    }
  }
  return gaps;
}

export function targetScopeGaps(report: unknown, origins: string[]): string[] {
  const targets = z
    .object({ targets: z.array(z.object({ target: z.string() })) })
    .safeParse(report);
  if (!targets.success)
    return ["Report does not contain a valid target inventory"];
  const origin = (value: string): string | undefined => {
    if (/[\s<>]/.test(value)) return undefined;
    if (value.includes("://") && !/^https?:\/\//i.test(value)) return undefined;
    try {
      const url = new URL(withHttpScheme(value));
      if (
        !["http:", "https:"].includes(url.protocol) ||
        url.username ||
        url.password
      )
        return undefined;
      return url.origin;
    } catch {
      return undefined;
    }
  };
  const allowed = new Set(
    origins.map(origin).filter((value) => value !== undefined),
  );
  return targets.data.targets.flatMap(({ target }) => {
    const candidate = origin(target);
    return candidate !== undefined && allowed.has(candidate)
      ? []
      : [
          `Recommended target is not a concrete authorized origin: ${target}. Keep discovered out-of-scope systems in the map, not in recommended test targets.`,
        ];
  });
}
