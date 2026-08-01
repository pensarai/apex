import path from "node:path";
import { normalizeRepositoryPath, shortHash } from "./identity";
import type {
  EvidenceBundle,
  ReconApplication,
  ReconCandidate,
  RepositoryInventory,
} from "./types";

export interface EvidenceBundleOptions {
  maxCharacters?: number;
  maxCandidates?: number;
}

const DEFAULT_MAX_CHARACTERS = 128_000;
const DEFAULT_MAX_CANDIDATES = 80;

export function createEvidenceBundles(
  candidates: ReconCandidate[],
  applications: ReconApplication[],
  inventory: RepositoryInventory,
  options: EvidenceBundleOptions = {},
): EvidenceBundle[] {
  const maxCharacters = Math.max(
    1,
    options.maxCharacters ?? DEFAULT_MAX_CHARACTERS,
  );
  const maxCandidates = Math.max(
    1,
    options.maxCandidates ?? DEFAULT_MAX_CANDIDATES,
  );
  const applicationRoots = applications
    .flatMap((application) =>
      application.source_roots.flatMap((root) => {
        const normalized = root === "." ? "." : normalizeRepositoryPath(root);
        return normalized
          ? [{ applicationId: application.id, root: normalized }]
          : [];
      }),
    )
    .sort((a, b) => b.root.length - a.root.length);
  const manifestRoots = inventory.files
    .filter((file) => file.kind === "manifest")
    .map((file) => path.posix.dirname(file.path))
    .sort((a, b) => b.length - a.length);
  const groups = new Map<
    string,
    { applicationIds: string[]; candidates: ReconCandidate[] }
  >();

  for (const candidate of [...candidates].sort(compareCandidates)) {
    const matchingApplications = applicationRoots.filter(({ root }) =>
      isWithinRoot(candidate.path, root),
    );
    const longestRoot = matchingApplications[0]?.root.length;
    const applicationIds = [
      ...new Set(
        matchingApplications
          .filter(({ root }) => root.length === longestRoot)
          .map(({ applicationId }) => applicationId),
      ),
    ].sort();
    const locality =
      matchingApplications[0]?.root ??
      manifestRoots.find((root) => isWithinRoot(candidate.path, root)) ??
      topLevel(candidate.path);
    const key = `${locality}\u0000${applicationIds.join("+")}`;
    const group = groups.get(key) ?? { applicationIds, candidates: [] };
    group.candidates.push(candidate);
    groups.set(key, group);
  }

  const bundles: EvidenceBundle[] = [];
  for (const [key, group] of [...groups.entries()].sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    const [locality = "."] = key.split("\u0000");
    let current: ReconCandidate[] = [];
    let characters = 0;
    const flush = () => {
      if (current.length === 0) return;
      const seed = current.map((candidate) => candidate.id).join("\n");
      bundles.push({
        id: `bundle-${shortHash(`${key}\n${seed}`, 18)}`,
        application_ids: group.applicationIds,
        locality,
        candidates: current,
      });
      current = [];
      characters = 0;
    };

    for (const component of dependencyComponents(group.candidates)) {
      const componentCharacters = component.reduce(
        (total, candidate) => total + JSON.stringify(candidate).length,
        0,
      );
      const componentFitsAlone =
        component.length <= maxCandidates &&
        componentCharacters <= maxCharacters;
      if (
        current.length > 0 &&
        componentFitsAlone &&
        (current.length + component.length > maxCandidates ||
          characters + componentCharacters > maxCharacters)
      ) {
        flush();
      }
      for (const candidate of component) {
        const candidateCharacters = JSON.stringify(candidate).length;
        if (
          current.length > 0 &&
          (current.length >= maxCandidates ||
            characters + candidateCharacters > maxCharacters)
        ) {
          flush();
        }
        current.push(candidate);
        characters += candidateCharacters;
      }
    }
    flush();
  }

  return bundles.sort((a, b) => a.id.localeCompare(b.id));
}

function dependencyComponents(
  candidates: ReconCandidate[],
): ReconCandidate[][] {
  const byPath = new Map<string, ReconCandidate[]>();
  for (const candidate of candidates) {
    const values = byPath.get(candidate.path) ?? [];
    values.push(candidate);
    byPath.set(candidate.path, values);
  }
  const adjacency = new Map<string, Set<string>>(
    [...byPath.keys()].map((filePath) => [filePath, new Set<string>()]),
  );
  for (const candidate of candidates) {
    for (const dependency of candidate.dependency_context) {
      if (!byPath.has(dependency.resolved_path)) continue;
      adjacency.get(candidate.path)?.add(dependency.resolved_path);
      adjacency.get(dependency.resolved_path)?.add(candidate.path);
    }
  }

  const components: ReconCandidate[][] = [];
  const visited = new Set<string>();
  for (const start of [...byPath.keys()].sort()) {
    if (visited.has(start)) continue;
    const queue = [start];
    const paths: string[] = [];
    visited.add(start);
    while (queue.length > 0) {
      const current = queue.shift();
      if (!current) continue;
      paths.push(current);
      for (const neighbor of [...(adjacency.get(current) ?? [])].sort()) {
        if (visited.has(neighbor)) continue;
        visited.add(neighbor);
        queue.push(neighbor);
      }
    }
    components.push(
      paths.flatMap((filePath) =>
        [...(byPath.get(filePath) ?? [])].sort(compareCandidates),
      ),
    );
  }
  return components;
}

export function estimateBundleInputTokens(bundle: EvidenceBundle): number {
  return Math.ceil(JSON.stringify(bundle).length / 3) + 2_000;
}

function isWithinRoot(filePath: string, root: string): boolean {
  return root === "." || filePath === root || filePath.startsWith(`${root}/`);
}

function topLevel(filePath: string): string {
  return filePath.split("/")[0] || ".";
}

function compareCandidates(a: ReconCandidate, b: ReconCandidate): number {
  return (
    a.path.localeCompare(b.path) ||
    a.line_start - b.line_start ||
    a.id.localeCompare(b.id)
  );
}
