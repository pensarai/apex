import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { writeRecord } from "../../offSecAgent/tools/topologyRecords";
import {
  completionSnapshot,
  structuralGaps,
  targetScopeGaps,
} from "./reconCompletionChecks";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function root() {
  const value = mkdtempSync(join(tmpdir(), "goal-checks-"));
  roots.push(value);
  return value;
}
describe("recon goal completion checks", () => {
  it("rejects dangling references without imposing a threat quota", () => {
    const dir = root();
    writeRecord(dir, "s", "component", "service", {
      id: "service",
      name: "Service",
      kind: "application",
    });
    expect(structuralGaps(dir)).toEqual([]);
    writeRecord(dir, "s", "threat", "path", {
      id: "path",
      componentId: "missing",
      title: "Path",
    });
    expect(structuralGaps(dir)).toEqual([
      "path: componentId references missing or retired record missing",
    ]);
  });
  it("binds ordered attack steps, not just the set of step texts", () => {
    const dir = root();
    const threat = {
      id: "path",
      title: "Path",
      attackSteps: ["Get access", "Read asset"],
    };
    writeRecord(dir, "s", "threat", "path", threat);
    const before = completionSnapshot(dir, { targets: [] });
    writeRecord(dir, "s", "threat", "path", {
      ...threat,
      attackSteps: [...threat.attackSteps].reverse(),
    });
    expect(completionSnapshot(dir, { targets: [] })).not.toBe(before);
  });
  it("ignores storage timestamps but detects a report change", () => {
    const dir = root();
    writeRecord(dir, "s", "component", "service", {
      id: "service",
      name: "Service",
      recordedAt: "first",
    });
    const before = completionSnapshot(dir, { targets: [] });
    writeRecord(dir, "s", "component", "service", {
      id: "service",
      name: "Service",
      recordedAt: "second",
    });
    expect(completionSnapshot(dir, { targets: [] })).toBe(before);
    expect(
      completionSnapshot(dir, { targets: [{ target: "https://app.example" }] }),
    ).not.toBe(before);
  });
  it("allows authorized origin paths while rejecting provider and non-HTTP targets", () => {
    const targets = [
      "https://app.example/path",
      "https://provider.example",
      "ssh://app.example",
      "https://user:pass@app.example",
      "https://app.example:8443",
    ];
    const gaps = targetScopeGaps(
      { targets: targets.map((target) => ({ target })) },
      ["https://app.example"],
    );
    expect(gaps).toHaveLength(4);
    expect(gaps.join(" ")).not.toContain("https://app.example/path");
    expect(targetScopeGaps({}, ["https://app.example"])).toEqual([
      "Report does not contain a valid target inventory",
    ]);
  });
});
