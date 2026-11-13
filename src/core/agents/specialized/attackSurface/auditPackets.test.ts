import { describe, expect, it } from "vitest";
import { buildAuditPackets } from "./auditPackets";

describe("audit evidence packets", () => {
  it("rejects a grouped record that disappeared rather than silently omitting it", () => {
    expect(() =>
      buildAuditPackets(
        [
          {
            id: "component:cmp_api",
            description: "Review the API",
            recordIds: ["cmp_api", "thr_missing"],
          },
        ],
        {
          components: [{ id: "cmp_api" }],
          threats: [],
          controls: [],
          flows: [],
          boundaries: [],
          retired: [],
        },
      ),
    ).toThrow("Audit record unavailable: thr_missing");
  });
  it("keeps the full connected review together, even when it needs file-backed evidence", () => {
    const component = { id: "cmp_api", name: "API" };
    const threat = {
      id: "thr_api",
      componentId: "cmp_api",
      evidence: "x".repeat(60_000),
    };
    const requirement = {
      id: "component:cmp_api",
      description: "Review connected claims",
      recordIds: [component.id, threat.id],
    };
    const packets = buildAuditPackets([requirement], {
      components: [component],
      threats: [threat],
      boundaries: [],
      controls: [],
      flows: [],
      retired: [],
    });
    expect(packets).toEqual([
      { requirements: [requirement], records: [component, threat] },
    ]);
  });
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
