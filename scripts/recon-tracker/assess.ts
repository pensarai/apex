import type { LoadedTopology } from "../../src/core/agents/offSecAgent/tools/topologyRecords";
import { inspectTracker, type ScopeItem } from "./scope";

export function mentionsHost(text: string, host: string): boolean {
  return new RegExp(
    `(?<![\\w.-])${host.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w.-])`,
    "i",
  ).test(text);
}

export function assessTopology(
  items: ScopeItem[],
  topology: LoadedTopology,
  tracker?: string,
) {
  const records = [
    topology.boundaries,
    topology.components,
    topology.flows,
    topology.controls,
    topology.threats,
  ].flat();
  const rows = items.map((item) => {
    const components = topology.components.filter((component) =>
      mentionsHost(JSON.stringify(component.endpoints ?? []), item.domain),
    );
    const componentIds = components.map((component) => component.id);
    const threats = topology.threats.filter((threat) =>
      componentIds.includes(String(threat.componentId)),
    );
    return {
      ...item,
      componentIds,
      threatIds: threats.map((threat) => threat.id),
      referencedRecordIds: records
        .filter((record) => mentionsHost(JSON.stringify(record), item.domain))
        .map((record) => record.id),
      retiredRecordIds: topology.retired
        .filter(({ record }) =>
          mentionsHost(JSON.stringify(record), item.domain),
        )
        .map(({ record }) => record.id),
    };
  });
  const depth = topology.components.map((component) => {
    const threats = topology.threats.filter(
      (threat) => threat.componentId === component.id,
    );
    return {
      id: component.id,
      name: component.name,
      threats: threats.length,
      withSteps: threats.filter(
        (t) => Array.isArray(t.attackSteps) && t.attackSteps.length >= 2,
      ).length,
      withPreconditions: threats.filter(
        (t) => Array.isArray(t.preconditions) && t.preconditions.length > 0,
      ).length,
      withImpact: threats.filter(
        (t) => typeof t.impact === "string" && t.impact.trim(),
      ).length,
    };
  });
  const trackerCheck =
    tracker === undefined ? undefined : inspectTracker(tracker, items);
  if (trackerCheck) {
    const componentIds = new Set(topology.components.map((c) => c.id));
    for (const row of trackerCheck.rows) {
      if (!["assessed", "covered_by_shared_model"].includes(row.status))
        continue;
      const refs = row.components.match(/cmp_[a-zA-Z0-9]+/g) ?? [];
      if (!refs.length || refs.some((id) => !componentIds.has(id)))
        trackerCheck.errors.push(`Unresolved component references: ${row.id}`);
    }
  }
  return {
    totalDomains: items.length,
    endpointMappedDomains: rows.filter((r) => r.componentIds.length).length,
    recordReferencedDomains: rows.filter((r) => r.referencedRecordIds.length)
      .length,
    retiredReferencedDomains: rows.filter((r) => r.retiredRecordIds.length)
      .length,
    anyRecordReferencedDomains: rows.filter(
      (r) => r.referencedRecordIds.length || r.retiredRecordIds.length,
    ).length,
    domainsMappedToThreats: rows.filter((r) => r.threatIds.length).length,
    unmappedDomains: rows
      .filter((r) => !r.componentIds.length)
      .map((r) => r.domain),
    componentsWithoutThreats: depth.filter((r) => !r.threats).length,
    componentsWithMultipleThreats: depth.filter((r) => r.threats > 1).length,
    rows,
    depth,
    trackerCheck,
    caveats: [
      "Host matching credits only explicit saved references, not implicit wildcard/family coverage.",
      "A component endpoint or threat link does not prove a completed assessment.",
      "Retired records are reported separately; retirement is a claimed disposition, not verified absence of risk.",
      "Threat fields and counts are review aids, not a quality score or vulnerability confirmation.",
      "Tracker dispositions and evidence references are model claims; only row integrity and component IDs are checked here.",
    ],
  };
}
