import { expect, it } from "vitest";
import { assessTopology, mentionsHost } from "./assess";
import { csv, loadScope, parseCsv, seedTracker } from "./scope";

it("does not credit a parent, suffix match or threat prose as an endpoint mapping", () => {
  expect(mentionsHost("https://app.example/path", "app.example")).toBe(true);
  expect(mentionsHost("https://dev.app.example", "app.example")).toBe(false);
  expect(mentionsHost("https://app.example.evil.test", "app.example")).toBe(
    false,
  );
  const items = loadScope("a.example\nb.example").items;
  const result = assessTopology(items, {
    retired: [],
    boundaries: [],
    flows: [],
    controls: [],
    components: [
      { id: "cmp_a", name: "Shared", endpoints: ["https://a.example"] },
    ],
    threats: [
      {
        id: "thr_a",
        componentId: "cmp_a",
        description: "b.example may share auth",
      },
    ],
  });
  expect(result.endpointMappedDomains).toBe(1);
  expect(result.recordReferencedDomains).toBe(2);
  expect(result.domainsMappedToThreats).toBe(1);
});

it("does not accept an invented component reference in the tracker", () => {
  const items = loadScope("a.example").items;
  const rows = parseCsv(seedTracker(items));
  rows[1] = [
    items[0].id,
    items[0].domain,
    "assessed",
    "cmp_invented",
    "probe.txt",
    "reviewed",
  ];
  const result = assessTopology(
    items,
    {
      components: [],
      threats: [],
      boundaries: [],
      flows: [],
      controls: [],
      retired: [],
    },
    csv(rows),
  );
  expect(result.trackerCheck?.errors).toContain(
    `Unresolved component references: ${items[0].id}`,
  );
  expect(result.endpointMappedDomains).toBe(0);
});

it("preserves retired dispositions without counting them as active models", () => {
  const result = assessTopology(loadScope("a.example\nb.example").items, {
    boundaries: [],
    components: [],
    flows: [],
    controls: [],
    threats: [],
    retired: [
      {
        kind: "component",
        record: {
          id: "cmp_a",
          endpoints: ["https://a.example"],
          status: "retired",
          retiredReason: "Redirect to another service",
        },
      },
    ],
  });
  expect(result.endpointMappedDomains).toBe(0);
  expect(result.recordReferencedDomains).toBe(0);
  expect(result.retiredReferencedDomains).toBe(1);
  expect(result.anyRecordReferencedDomains).toBe(1);
  expect(result.rows[0].retiredRecordIds).toEqual(["cmp_a"]);
  expect(result.rows[1].retiredRecordIds).toEqual([]);
});

it("reports truncated assessed rows without crashing the comparison", () => {
  const items = loadScope("a.example").items;
  const rows = parseCsv(seedTracker(items));
  rows[1] = [items[0].id, items[0].domain, "assessed"];
  const result = assessTopology(
    items,
    {
      components: [],
      threats: [],
      boundaries: [],
      flows: [],
      controls: [],
      retired: [],
    },
    csv(rows),
  );
  expect(result.trackerCheck?.errors).toContain(
    `Wrong column count: ${items[0].id}`,
  );
  expect(result.trackerCheck?.errors).toContain(
    `Unsupported assessment fields: ${items[0].id}`,
  );
});
