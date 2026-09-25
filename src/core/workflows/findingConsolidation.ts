import { randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import type {
  FindingConsolidation,
  FindingsRegistry,
} from "../findings/registry";
import { findingReferenceId } from "../findings/registry";

export const FINDING_CONSOLIDATION_RELATIVE_PATH =
  "coordination/finding-consolidation.json";

function artifactPath(sessionRootPath: string): string {
  return join(sessionRootPath, FINDING_CONSOLIDATION_RELATIVE_PATH);
}

function readArtifact(path: string): FindingConsolidation {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as FindingConsolidation;
  if (
    parsed.version !== 1 ||
    typeof parsed.completedAt !== "string" ||
    !Array.isArray(parsed.findingIds) ||
    !Array.isArray(parsed.duplicateSets) ||
    !Array.isArray(parsed.rootCauseGroups)
  ) {
    throw new Error("Invalid finding consolidation artifact");
  }
  return parsed;
}

function atomicWrite(path: string, value: FindingConsolidation): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  renameSync(temporaryPath, path);
}

export async function ensureFindingConsolidation(
  sessionRootPath: string,
  registry: FindingsRegistry,
): Promise<FindingConsolidation> {
  const path = artifactPath(sessionRootPath);
  if (existsSync(path)) {
    const artifact = readArtifact(path);
    const currentIds = registry.getFindings().map(findingReferenceId).sort();
    if (
      JSON.stringify([...artifact.findingIds].sort()) ===
      JSON.stringify(currentIds)
    ) {
      registry.applyConsolidation(artifact);
      return artifact;
    }
  }
  const artifact =
    typeof registry.consolidate === "function"
      ? await registry.consolidate()
      : {
          version: 1 as const,
          completedAt: new Date().toISOString(),
          findingIds: registry.getFindings().map(findingReferenceId),
          duplicateSets: [],
          rootCauseGroups: [],
        };
  atomicWrite(path, artifact);
  return artifact;
}
