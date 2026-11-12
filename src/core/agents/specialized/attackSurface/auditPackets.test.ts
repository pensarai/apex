import { describe, expect, it } from "vitest";
import { buildAuditPackets } from "./auditPackets";

describe("audit evidence packets", () => {
  it("splits large evidence without truncating it or losing a retired requirement", () => {
    const components = Array.from({ length: 13 }, (_, n) => ({
      id: `cmp_${n}`,
      name: `Service ${n}`,
      evidence: "文".repeat(10_000),
    }));
    const retired = {
      id: "cmp_retired",
      status: "retired",
      retiredReason: "Duplicate",
    };
    const requirements = [
      { id: "objective", description: "Review the whole objective" },
      ...[...components, retired].map((record) => ({
        id: `component:${record.id}`,
        description: "Review evidence",
      })),
    ];
    const packets = buildAuditPackets(requirements, {
      components,
      retired: [{ kind: "component", record: retired }],
      boundaries: [],
      controls: [],
      threats: [],
      flows: [],
    });
    expect(packets.flatMap((packet) => packet.records)).toEqual([
      ...components,
      retired,
    ]);
    expect(
      packets.every(
        (packet) => Buffer.byteLength(JSON.stringify(packet.records)) <= 48_000,
      ),
    ).toBe(true);
    expect(packets.at(-1)!.requirements).toEqual([requirements[0]]);
    expect(packets.flatMap((packet) => packet.requirements)).toHaveLength(
      requirements.length,
    );
  });
});
