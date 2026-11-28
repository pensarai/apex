import { describe, expect, it } from "vitest";
import { csv, inspectTracker, loadScope, parseCsv, seedTracker } from "./scope";

describe("recon scope and tracker", () => {
  it("deduplicates by host while preserving original order and stable identity", () => {
    const result = loadScope(
      '\uFEFF,,,,\r\n"APP.example",,,,\r\nhttps://app.example/,,,,\r\napi.example,,,,',
    );
    expect(result.inputRows).toBe(3);
    expect(result.duplicates).toBe(1);
    expect(result.items.map((r) => r.domain)).toEqual([
      "app.example",
      "api.example",
    ]);
    expect(loadScope("api.example\napp.example").items[1].id).toBe(
      result.items[0].id,
    );
  });
  it("preserves quoted evidence, commas, quotes and multiline notes", () => {
    const rows = [
      ["id", "note"],
      ["1", 'Headers: "ok",\nsecond line'],
    ];
    expect(parseCsv(csv(rows))).toEqual(rows);
    expect(() => parseCsv('"unfinished')).toThrow();
    expect(() => parseCsv('"closed"tail')).toThrow();
  });
  it("rejects unexpected scope data instead of silently dropping it", () => {
    for (const input of [
      "https://a.example/private",
      "*.example",
      "a.example,other",
      ",a.example",
      '"a.\nexample"',
      "https://u:p@a.example",
      "",
    ])
      expect(() => loadScope(input)).toThrow();
  });
  it("detects forgotten, duplicated, invented and unsupported complete rows", () => {
    const items = loadScope("a.example\nb.example").items;
    const seeded = seedTracker(items);
    expect(inspectTracker(seeded, items).pending).toBe(2);
    const rows = parseCsv(seeded);
    rows.pop();
    rows[1][2] = "assessed";
    rows.push([...rows[1]], ["invented", "c.example", "excluded", "", "", ""]);
    const result = inspectTracker(csv(rows), items);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        `Missing row: ${items[1].id}`,
        `Duplicate row: ${items[0].id}`,
        `Unsupported assessment fields: ${items[0].id}`,
        "Unknown or changed scope row: invented",
      ]),
    );
  });
});
