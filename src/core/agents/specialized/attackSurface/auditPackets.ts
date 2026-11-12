import type {
  LoadedTopology,
  TopologyRecord,
} from "../../offSecAgent/tools/topologyRecords";
import type { AuditRequirement } from "./completionAudit";

const MAX_REQUIREMENTS = 12;
const MAX_RECORD_BYTES = 48_000;

export function buildAuditPackets(
  requirements: AuditRequirement[],
  topology: LoadedTopology,
) {
  const records = [
    ...topology.boundaries,
    ...topology.components,
    ...topology.flows,
    ...topology.controls,
    ...topology.threats,
    ...topology.retired.map((item) => item.record),
  ];
  const byId = new Map(records.map((record) => [record.id, record]));
  const recordFor = (requirement: AuditRequirement) =>
    byId.get(requirement.id.slice(requirement.id.indexOf(":") + 1));
  const packets: {
    requirements: AuditRequirement[];
    records: TopologyRecord[];
  }[] = [];
  let current: (typeof packets)[number] = { requirements: [], records: [] };
  for (const requirement of requirements.filter(recordFor)) {
    const record = recordFor(requirement)!;
    if (
      current.requirements.length &&
      (current.requirements.length >= MAX_REQUIREMENTS ||
        Buffer.byteLength(JSON.stringify([...current.records, record])) >
          MAX_RECORD_BYTES)
    ) {
      packets.push(current);
      current = { requirements: [], records: [] };
    }
    current.requirements.push(requirement);
    current.records.push(record);
  }
  if (current.requirements.length) packets.push(current);
  const global = requirements
    .filter((requirement) => !recordFor(requirement))
    .sort((a, b) => Number(!a.id.includes(":")) - Number(!b.id.includes(":")));
  if (packets.length <= 1 && requirements.length <= MAX_REQUIREMENTS) {
    return [{ requirements, records }];
  }
  for (let offset = 0; offset < global.length; offset += MAX_REQUIREMENTS)
    packets.push({
      requirements: global.slice(offset, offset + MAX_REQUIREMENTS),
      records: [],
    });
  return packets;
}

export function auditRecordIndex(record: TopologyRecord) {
  return Object.fromEntries(
    Object.entries(record).filter(
      ([key]) =>
        ["id", "name", "title", "kind", "status", "retiredReason"].includes(
          key,
        ) ||
        (key.endsWith("Id") && key !== "sessionId") ||
        key.endsWith("Ids"),
    ),
  );
}
