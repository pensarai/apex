import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FindingConsolidation } from "../findings/registry";
import {
  ensureFindingConsolidation,
  FINDING_CONSOLIDATION_RELATIVE_PATH,
} from "./findingConsolidation";

function finding(id: string) {
  return {
    id,
    title: id,
    description: "description",
    endpoint: "https://example.test",
    severity: "HIGH" as const,
    impact: "impact",
    evidence: "evidence",
    pocPath: "poc.sh",
    remediation: "remediation",
  };
}

function consolidation(findingIds: string[]): FindingConsolidation {
  return {
    version: 1,
    completedAt: "2026-09-19T00:00:00.000Z",
    findingIds,
    duplicateSets: [],
    rootCauseGroups: [],
  };
}

describe("ensureFindingConsolidation", () => {
  const roots: string[] = [];

  afterEach(() => {
    for (const root of roots) rmSync(root, { recursive: true, force: true });
    roots.length = 0;
  });

  it("restores a matching sealed artifact without another model call", async () => {
    const root = mkdtempSync(join(tmpdir(), "finding-consolidation-"));
    roots.push(root);
    const artifact = consolidation(["finding_a"]);
    const registry = {
      getFindings: () => [finding("finding_a")],
      consolidate: vi.fn(async () => artifact),
      applyConsolidation: vi.fn(),
    };

    await ensureFindingConsolidation(root, registry as never);
    const restored = await ensureFindingConsolidation(root, registry as never);

    expect(restored).toEqual(artifact);
    expect(registry.consolidate).toHaveBeenCalledTimes(1);
    expect(registry.applyConsolidation).toHaveBeenCalledWith(artifact);
  });

  it("recomputes atomically when the finding set changes", async () => {
    const root = mkdtempSync(join(tmpdir(), "finding-consolidation-"));
    roots.push(root);
    let findings = [finding("finding_a")];
    const registry = {
      getFindings: () => findings,
      consolidate: vi
        .fn()
        .mockResolvedValueOnce(consolidation(["finding_a"]))
        .mockResolvedValueOnce(consolidation(["finding_a", "finding_b"])),
      applyConsolidation: vi.fn(),
    };

    await ensureFindingConsolidation(root, registry as never);
    findings = [finding("finding_a"), finding("finding_b")];
    const refreshed = await ensureFindingConsolidation(root, registry as never);

    expect(refreshed.findingIds).toEqual(["finding_a", "finding_b"]);
    expect(registry.consolidate).toHaveBeenCalledTimes(2);
    const persisted = JSON.parse(
      readFileSync(join(root, FINDING_CONSOLIDATION_RELATIVE_PATH), "utf8"),
    ) as FindingConsolidation;
    expect(persisted.findingIds).toEqual(["finding_a", "finding_b"]);
  });
});
