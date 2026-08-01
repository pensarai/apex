import {
  canonicalApplicationId,
  normalizeRepositoryPath,
  normalizeStringSet,
  observationId,
  resourceIdentity,
  surfaceIdentity,
} from "./identity";
import type {
  ApplicationCandidate,
  EvidenceBundle,
  InventoryFile,
  PlannerResult,
  ReconApplication,
  ReconciliationResult,
  ReconResource,
  ReconSurface,
  ResourceCandidate,
  SurfaceCandidate,
  UnresolvedItem,
  WorkerResult,
} from "./types";

interface StoredSurface {
  observationId: string;
  value: ReconSurface;
}

interface StoredResource {
  observationId: string;
  value: ReconResource;
}

export interface RegistryCandidateMetrics {
  total: number;
  accepted: number;
  persisted: number;
  duplicate: number;
  rejected: number;
  unresolved: number;
}

export interface ReconciliationSnapshot {
  applications: ReconApplication[];
  surfaces: Array<{ observation_id: string; value: ReconSurface }>;
  resources: Array<{ observation_id: string; value: ReconResource }>;
  unresolved: UnresolvedItem[];
}

export class ReconRegistry {
  private readonly inventoryPaths: Set<string>;
  private readonly analyzablePaths: Set<string>;
  private readonly lineCounts: Map<string, number>;
  private readonly applications = new Map<string, ReconApplication>();
  private readonly applicationAliases = new Map<string, string>();
  private readonly surfaces = new Map<string, StoredSurface>();
  private readonly resources = new Map<string, StoredResource>();
  private readonly surfaceIdentities = new Set<string>();
  private readonly resourceIdentities = new Set<string>();
  private readonly persistedCandidateIds = new Set<string>();
  private readonly unresolvedItems: UnresolvedItem[] = [];
  private readonly candidateMetrics: RegistryCandidateMetrics = {
    total: 0,
    accepted: 0,
    persisted: 0,
    duplicate: 0,
    rejected: 0,
    unresolved: 0,
  };

  constructor(files: InventoryFile[]) {
    this.inventoryPaths = new Set(files.map((file) => file.path));
    this.analyzablePaths = new Set(
      files
        .filter((file) => file.relevance === "analyze")
        .map((file) => file.path),
    );
    this.lineCounts = new Map(
      files.flatMap((file) =>
        file.line_count === undefined ? [] : [[file.path, file.line_count]],
      ),
    );
  }

  ingestPlanner(result: PlannerResult): void {
    for (const candidate of result.applications) {
      this.ingestApplication(candidate);
    }
    this.unresolvedItems.push(...result.unresolved);
  }

  ingestWorker(result: WorkerResult, bundle: EvidenceBundle): void {
    const assignedCandidateIds = new Set(
      bundle.candidates.map((candidate) => candidate.id),
    );
    const localAliases = new Map<string, string>();
    for (const candidate of result.applications) {
      if (
        candidate.disposition === "accepted" &&
        (candidate.candidate_ids.length === 0 ||
          candidate.candidate_ids.some((id) => !assignedCandidateIds.has(id)))
      ) {
        this.addUnresolved({
          kind: "application",
          summary: candidate.name,
          source_files: candidate.source_roots,
          reason: "application-candidate-evidence-outside-bundle",
        });
        continue;
      }
      const id = this.ingestApplication(candidate);
      if (id) localAliases.set(candidate.id, id);
    }

    result.surfaces.forEach((candidate) => {
      if (
        candidate.disposition === "accepted" &&
        !this.surfaceHasBundleEvidence(candidate, bundle)
      ) {
        this.rejectUnsupportedRecord(
          "surface",
          candidate.path_or_name,
          candidate.source_file,
          "surface-source-not-in-candidate-evidence",
        );
        return;
      }
      this.ingestSurface(candidate, result.bundle_id, localAliases);
    });
    result.resources.forEach((candidate) => {
      if (
        candidate.disposition === "accepted" &&
        !this.resourceHasBundleEvidence(candidate, bundle)
      ) {
        this.rejectUnsupportedRecord(
          "resource",
          candidate.identifier,
          candidate.source_file,
          "resource-source-not-in-candidate-evidence",
        );
        return;
      }
      this.ingestResource(candidate, result.bundle_id, localAliases);
    });
    this.unresolvedItems.push(...result.unresolved);
  }

  ingestDeterministicSurface(surface: ReconSurface): void {
    this.ingestSurface(
      {
        ...surface,
        candidate_id: observationId(
          "surface",
          `formal:${surfaceIdentity(surface)}`,
        ),
        disposition: "accepted",
      },
      "formal-artifact",
      new Map(),
    );
  }

  ingestDeterministicResource(resource: ReconResource): void {
    this.ingestResource(
      {
        ...resource,
        candidate_id: observationId(
          "resource",
          `config:${resourceIdentity(resource)}`,
        ),
        disposition: "accepted",
      },
      "config-artifact",
      new Map(),
    );
  }

  addApplicationDomain(applicationId: string, domain: string): void {
    const id = this.resolveApplicationId(applicationId);
    const application = id ? this.applications.get(id) : undefined;
    if (!id || !application) {
      this.addUnresolved({
        kind: "application-assignment",
        summary: `Could not assign configured domain ${domain}`,
        source_files: [],
        reason: `unknown-application:${applicationId}`,
      });
      return;
    }
    this.applications.set(id, {
      ...application,
      domains: normalizeStringSet([
        ...application.domains,
        domain.trim().toLowerCase(),
      ]),
    });
  }

  resolveApplicationReference(applicationId: string): string | null {
    return this.resolveApplicationId(applicationId);
  }

  applyReconciliation(result: ReconciliationResult): void {
    for (const merge of result.application_merges) {
      const sourceId = this.resolveApplicationId(merge.source_application_id);
      const targetId = this.resolveApplicationId(merge.target_application_id);
      if (!sourceId || !targetId || sourceId === targetId) {
        this.addUnresolved({
          kind: "conflict",
          summary: `Could not merge ${merge.source_application_id} into ${merge.target_application_id}`,
          source_files: [],
          reason: merge.reason,
        });
        continue;
      }
      const source = this.applications.get(sourceId);
      const target = this.applications.get(targetId);
      if (!source || !target) continue;
      const [survivingId, removedId] = [sourceId, targetId].sort();
      const surviving = this.applications.get(survivingId);
      const removed = this.applications.get(removedId);
      if (!surviving || !removed) continue;
      this.applications.set(survivingId, mergeApplications(surviving, removed));
      this.applications.delete(removedId);
      this.applicationAliases.set(removedId, survivingId);
    }

    for (const update of result.application_updates) {
      const id = this.resolveApplicationId(update.application_id);
      const application = id ? this.applications.get(id) : undefined;
      if (!id || !application) {
        this.addUnresolved({
          kind: "application",
          summary: `Could not update unknown application ${update.application_id}`,
          source_files: [],
          reason: update.reason,
        });
        continue;
      }
      const updateRoots = (update.source_roots ?? []).flatMap((root) => {
        const normalized = normalizeSourceRoot(root);
        if (normalized && this.hasSourceRoot(normalized)) return [normalized];
        this.addUnresolved({
          kind: "application",
          summary: `Invalid source root for ${application.name}`,
          source_files: [],
          reason: `invalid-source-root:${root}`,
        });
        return [];
      });
      this.applications.set(id, {
        ...application,
        name: update.name ?? application.name,
        source_roots: normalizeStringSet([
          ...application.source_roots,
          ...updateRoots,
        ]),
        languages: normalizeStringSet([
          ...application.languages,
          ...(update.languages ?? []),
        ]),
        frameworks: normalizeStringSet([
          ...application.frameworks,
          ...(update.frameworks ?? []),
        ]),
        domains: normalizeStringSet([
          ...application.domains,
          ...(update.domains ?? []),
        ]),
      });
    }

    for (const reassignment of result.surface_reassignments) {
      const stored = this.surfaces.get(reassignment.observation_id);
      const applicationId = this.resolveApplicationId(
        reassignment.application_id,
      );
      if (!stored || !applicationId) {
        this.addUnresolved({
          kind: "application-assignment",
          summary: `Could not reassign surface ${reassignment.observation_id}`,
          source_files: stored ? [stored.value.source_file] : [],
          reason: reassignment.reason,
        });
        continue;
      }
      stored.value.application_id = applicationId;
    }

    for (const reassignment of result.resource_reassignments) {
      const stored = this.resources.get(reassignment.observation_id);
      const applicationId = this.resolveApplicationId(
        reassignment.application_id,
      );
      if (!stored || !applicationId) {
        this.addUnresolved({
          kind: "application-assignment",
          summary: `Could not reassign resource ${reassignment.observation_id}`,
          source_files: stored ? [stored.value.source_file] : [],
          reason: reassignment.reason,
        });
        continue;
      }
      stored.value.application_id = applicationId;
    }

    for (const disposition of result.surface_dispositions) {
      const stored = this.surfaces.get(disposition.observation_id);
      if (!stored) {
        this.addUnresolved({
          kind: "conflict",
          summary: `Unknown surface observation ${disposition.observation_id}`,
          source_files: [],
          reason: disposition.reason,
        });
        continue;
      }
      this.surfaces.delete(disposition.observation_id);
      if (disposition.disposition === "unresolved") {
        this.addUnresolved({
          kind: "surface",
          summary: `${stored.value.method ?? stored.value.type} ${stored.value.path_or_name}`,
          source_files: [stored.value.source_file],
          reason: disposition.reason,
        });
      }
    }

    for (const disposition of result.resource_dispositions) {
      const stored = this.resources.get(disposition.observation_id);
      if (!stored) {
        this.addUnresolved({
          kind: "conflict",
          summary: `Unknown resource observation ${disposition.observation_id}`,
          source_files: [],
          reason: disposition.reason,
        });
        continue;
      }
      this.resources.delete(disposition.observation_id);
      if (disposition.disposition === "unresolved") {
        this.addUnresolved({
          kind: "resource",
          summary: stored.value.identifier,
          source_files: [stored.value.source_file],
          reason: disposition.reason,
        });
      }
    }

    this.unresolvedItems.push(...result.unresolved);
  }

  addUnresolved(item: UnresolvedItem): void {
    this.unresolvedItems.push(item);
  }

  getApplications(): ReconApplication[] {
    return [...this.applications.values()]
      .map((application) => ({
        ...application,
        source_roots: normalizeStringSet(application.source_roots),
        languages: normalizeStringSet(application.languages),
        frameworks: normalizeStringSet(application.frameworks),
        domains: normalizeStringSet(application.domains),
      }))
      .sort((a, b) => a.id.localeCompare(b.id));
  }

  getSurfaces(): ReconSurface[] {
    const deduplicated = new Map<string, ReconSurface>();
    const storedSurfaces = [...this.surfaces.values()].sort((a, b) =>
      a.observationId.localeCompare(b.observationId),
    );
    for (const stored of storedSurfaces) {
      const value = {
        ...stored.value,
        application_id:
          this.resolveApplicationId(stored.value.application_id) ??
          stored.value.application_id,
      };
      const key = surfaceIdentity(value);
      if (!deduplicated.has(key)) deduplicated.set(key, value);
    }
    return [...deduplicated.values()].sort(compareSurfaces);
  }

  getResources(): ReconResource[] {
    const deduplicated = new Map<string, ReconResource>();
    const storedResources = [...this.resources.values()].sort((a, b) =>
      a.observationId.localeCompare(b.observationId),
    );
    for (const stored of storedResources) {
      const value = {
        ...stored.value,
        application_id:
          this.resolveApplicationId(stored.value.application_id) ??
          stored.value.application_id,
      };
      const key = resourceIdentity(value);
      if (!deduplicated.has(key)) deduplicated.set(key, value);
    }
    return [...deduplicated.values()].sort(compareResources);
  }

  getUnresolved(): UnresolvedItem[] {
    const deduplicated = new Map<string, UnresolvedItem>();
    for (const item of this.unresolvedItems) {
      const normalized = {
        ...item,
        source_files: normalizeStringSet(item.source_files),
      };
      const key = JSON.stringify(normalized);
      if (!deduplicated.has(key)) deduplicated.set(key, normalized);
    }
    return [...deduplicated.values()].sort((a, b) =>
      `${a.kind}:${a.summary}`.localeCompare(`${b.kind}:${b.summary}`),
    );
  }

  getCandidateMetrics(): RegistryCandidateMetrics {
    return { ...this.candidateMetrics };
  }

  getPersistedCandidateIds(): Set<string> {
    return new Set(this.persistedCandidateIds);
  }

  reconciliationSnapshot(): ReconciliationSnapshot {
    return {
      applications: this.getApplications(),
      surfaces: [...this.surfaces.values()]
        .map((stored) => ({
          observation_id: stored.observationId,
          value: { ...stored.value },
        }))
        .sort((a, b) => a.observation_id.localeCompare(b.observation_id)),
      resources: [...this.resources.values()]
        .map((stored) => ({
          observation_id: stored.observationId,
          value: { ...stored.value },
        }))
        .sort((a, b) => a.observation_id.localeCompare(b.observation_id)),
      unresolved: this.getUnresolved(),
    };
  }

  needsReconciliation(): boolean {
    const applications = this.getApplications();
    for (let index = 0; index < applications.length; index++) {
      const application = applications[index];
      if (!application) continue;
      for (const other of applications.slice(index + 1)) {
        if (
          application.name.toLowerCase() === other.name.toLowerCase() ||
          application.source_roots.some((root) =>
            other.source_roots.includes(root),
          )
        ) {
          return true;
        }
      }
    }
    return this.unresolvedItems.some((item) =>
      ["application-assignment", "conflict", "relationship"].includes(
        item.kind,
      ),
    );
  }

  private ingestApplication(candidate: ApplicationCandidate): string | null {
    if (candidate.disposition === "rejected") return null;
    if (candidate.disposition === "unresolved") {
      this.addUnresolved({
        kind: "application",
        summary: candidate.name,
        source_files: candidate.source_roots,
        reason:
          candidate.disposition_reason ?? "application-candidate-unresolved",
      });
      return null;
    }

    const normalized: ReconApplication = {
      id: "",
      name: candidate.name.trim(),
      source_roots: normalizeStringSet(
        candidate.source_roots
          .map(normalizeSourceRoot)
          .filter(Boolean) as string[],
      ),
      languages: normalizeStringSet(candidate.languages),
      frameworks: normalizeStringSet(candidate.frameworks),
      domains: normalizeStringSet(candidate.domains),
    };
    if (normalized.source_roots.length === 0) {
      this.addUnresolved({
        kind: "application",
        summary: normalized.name,
        source_files: [],
        reason: "application-has-no-source-root",
      });
    }
    for (const root of normalized.source_roots) {
      if (!this.hasSourceRoot(root)) {
        this.addUnresolved({
          kind: "application",
          summary: normalized.name,
          source_files: [root],
          reason: "application-source-root-not-present-in-inventory",
        });
      }
    }
    normalized.id = canonicalApplicationId(normalized);
    const existing = this.applications.get(normalized.id);
    this.applications.set(
      normalized.id,
      existing ? mergeApplications(existing, normalized) : normalized,
    );
    this.applicationAliases.set(candidate.id, normalized.id);
    for (const id of candidate.candidate_ids) {
      this.persistedCandidateIds.add(id);
    }
    return normalized.id;
  }

  private ingestSurface(
    candidate: SurfaceCandidate,
    shardId: string,
    localAliases: Map<string, string>,
  ): void {
    this.candidateMetrics.total++;
    if (!this.shouldAcceptCandidate(candidate, "surface")) return;

    const applicationId = this.resolveApplicationId(
      localAliases.get(candidate.application_id) ?? candidate.application_id,
    );
    const sourceFile = normalizeRepositoryPath(candidate.source_file);
    const handlerFile = candidate.handler_file
      ? normalizeRepositoryPath(candidate.handler_file)
      : undefined;
    if (
      !applicationId ||
      !sourceFile ||
      !this.analyzablePaths.has(sourceFile)
    ) {
      this.markCandidateUnresolved(
        "surface",
        candidate.path_or_name,
        sourceFile ? [sourceFile] : [],
        !applicationId
          ? `unknown-application:${candidate.application_id}`
          : "source-file-not-analyzable-in-inventory",
      );
      return;
    }
    if (handlerFile && !this.analyzablePaths.has(handlerFile)) {
      this.markCandidateUnresolved(
        "surface",
        candidate.path_or_name,
        [sourceFile],
        "handler-file-not-analyzable-in-inventory",
      );
      return;
    }
    if (!this.isValidLine(sourceFile, candidate.source_line)) {
      this.markCandidateUnresolved(
        "surface",
        candidate.path_or_name,
        [sourceFile],
        "surface-source-line-outside-file",
      );
      return;
    }
    if (
      handlerFile &&
      candidate.handler_line !== undefined &&
      !this.isValidLine(handlerFile, candidate.handler_line)
    ) {
      this.markCandidateUnresolved(
        "surface",
        candidate.path_or_name,
        [sourceFile, handlerFile],
        "surface-handler-line-outside-file",
      );
      return;
    }
    if (candidate.type === "http" && !candidate.method) {
      this.markCandidateUnresolved(
        "surface",
        candidate.path_or_name,
        [sourceFile],
        "http-surface-missing-method",
      );
      return;
    }

    const value: ReconSurface = {
      application_id: applicationId,
      type: candidate.type,
      method: candidate.method?.toUpperCase(),
      path_or_name: candidate.path_or_name,
      source_file: sourceFile,
      source_line: candidate.source_line,
      handler_file: handlerFile ?? undefined,
      handler_line: candidate.handler_line,
    };
    const identity = surfaceIdentity(value);
    if (this.surfaceIdentities.has(identity)) {
      this.candidateMetrics.duplicate++;
      return;
    }
    const id = observationId(
      "surface",
      `${shardId}:${identity}:${JSON.stringify(value)}`,
    );
    if (this.surfaces.has(id)) {
      this.candidateMetrics.duplicate++;
      return;
    }
    this.surfaces.set(id, { observationId: id, value });
    this.surfaceIdentities.add(identity);
    this.persistedCandidateIds.add(candidate.candidate_id);
    this.candidateMetrics.accepted++;
    this.candidateMetrics.persisted++;
    if (
      value.source_line === 0 ||
      (value.handler_file && value.handler_line === 0)
    ) {
      this.addUnresolved({
        kind: "surface",
        summary: `${value.method ?? value.type} ${value.path_or_name}`,
        source_files: [value.source_file],
        reason: "source-location-not-fully-resolved",
      });
    }
  }

  private ingestResource(
    candidate: ResourceCandidate,
    shardId: string,
    localAliases: Map<string, string>,
  ): void {
    this.candidateMetrics.total++;
    if (!this.shouldAcceptCandidate(candidate, "resource")) return;

    const applicationId = this.resolveApplicationId(
      localAliases.get(candidate.application_id) ?? candidate.application_id,
    );
    const sourceFile = normalizeRepositoryPath(candidate.source_file);
    if (
      !applicationId ||
      !sourceFile ||
      !this.analyzablePaths.has(sourceFile)
    ) {
      this.markCandidateUnresolved(
        "resource",
        candidate.identifier,
        sourceFile ? [sourceFile] : [],
        !applicationId
          ? `unknown-application:${candidate.application_id}`
          : "source-file-not-analyzable-in-inventory",
      );
      return;
    }
    if (
      candidate.source_line !== undefined &&
      !this.isValidLine(sourceFile, candidate.source_line)
    ) {
      this.markCandidateUnresolved(
        "resource",
        candidate.identifier,
        [sourceFile],
        "resource-source-line-outside-file",
      );
      return;
    }

    const value: ReconResource = {
      application_id: applicationId,
      type: candidate.type,
      provider: candidate.provider,
      identifier: candidate.identifier,
      source_file: sourceFile,
      source_line: candidate.source_line,
    };
    const identity = resourceIdentity(value);
    if (this.resourceIdentities.has(identity)) {
      this.candidateMetrics.duplicate++;
      return;
    }
    const id = observationId(
      "resource",
      `${shardId}:${identity}:${JSON.stringify(value)}`,
    );
    if (this.resources.has(id)) {
      this.candidateMetrics.duplicate++;
      return;
    }
    this.resources.set(id, { observationId: id, value });
    this.resourceIdentities.add(identity);
    this.persistedCandidateIds.add(candidate.candidate_id);
    this.candidateMetrics.accepted++;
    this.candidateMetrics.persisted++;
  }

  private shouldAcceptCandidate(
    candidate: SurfaceCandidate | ResourceCandidate,
    kind: "surface" | "resource",
  ): boolean {
    if (candidate.disposition === "accepted") return true;
    if (candidate.disposition === "duplicate") {
      this.candidateMetrics.duplicate++;
      return false;
    }
    if (candidate.disposition === "rejected") {
      this.candidateMetrics.rejected++;
      return false;
    }
    this.markCandidateUnresolved(
      kind,
      "path_or_name" in candidate
        ? candidate.path_or_name
        : candidate.identifier,
      [candidate.source_file],
      candidate.disposition_reason ?? `${kind}-candidate-unresolved`,
    );
    return false;
  }

  private markCandidateUnresolved(
    kind: "surface" | "resource",
    summary: string,
    sourceFiles: string[],
    reason: string,
  ): void {
    this.candidateMetrics.unresolved++;
    this.addUnresolved({
      kind,
      summary,
      source_files: sourceFiles,
      reason,
    });
  }

  private rejectUnsupportedRecord(
    kind: "surface" | "resource",
    summary: string,
    sourceFile: string,
    reason: string,
  ): void {
    this.candidateMetrics.total++;
    this.markCandidateUnresolved(kind, summary, [sourceFile], reason);
  }

  private surfaceHasBundleEvidence(
    candidate: SurfaceCandidate,
    bundle: EvidenceBundle,
  ): boolean {
    if (
      !candidateLocationIsVisible(
        bundle,
        candidate.candidate_id,
        candidate.source_file,
        candidate.source_line,
      )
    ) {
      return false;
    }
    if (!candidate.handler_file) return true;
    return bundleLocationIsVisible(
      bundle,
      candidate.handler_file,
      candidate.handler_line,
    );
  }

  private resourceHasBundleEvidence(
    candidate: ResourceCandidate,
    bundle: EvidenceBundle,
  ): boolean {
    return candidateLocationIsVisible(
      bundle,
      candidate.candidate_id,
      candidate.source_file,
      candidate.source_line,
    );
  }

  private resolveApplicationId(id: string): string | null {
    let current = this.applicationAliases.get(id) ?? id;
    const seen = new Set<string>();
    while (this.applicationAliases.has(current) && !seen.has(current)) {
      seen.add(current);
      const next = this.applicationAliases.get(current);
      if (!next) break;
      current = next;
    }
    return this.applications.has(current) ? current : null;
  }

  private hasSourceRoot(root: string): boolean {
    return (
      root === "." ||
      [...this.inventoryPaths].some(
        (filePath) => filePath === root || filePath.startsWith(`${root}/`),
      )
    );
  }

  private isValidLine(filePath: string, line: number): boolean {
    if (line === 0) return true;
    const lineCount = this.lineCounts.get(filePath);
    return lineCount !== undefined && line <= lineCount;
  }
}

function candidateLocationIsVisible(
  bundle: EvidenceBundle,
  candidateId: string,
  sourceFile: string,
  sourceLine: number | undefined,
): boolean {
  const evidence = bundle.candidates.find(
    (candidate) => candidate.id === candidateId,
  );
  const normalized = normalizeRepositoryPath(sourceFile);
  return Boolean(
    evidence &&
      normalized === evidence.path &&
      lineIsVisible(evidence.snippet, sourceLine),
  );
}

function bundleLocationIsVisible(
  bundle: EvidenceBundle,
  sourceFile: string,
  sourceLine: number | undefined,
): boolean {
  const normalized = normalizeRepositoryPath(sourceFile);
  return bundle.candidates.some(
    (candidate) =>
      candidate.path === normalized &&
      lineIsVisible(candidate.snippet, sourceLine),
  );
}

function lineIsVisible(snippet: string, line: number | undefined): boolean {
  if (line === undefined || line === 0) return true;
  return snippet.split("\n").some((entry) => {
    const match = entry.match(/^\s*(\d+)\|/);
    return match?.[1] !== undefined && Number(match[1]) === line;
  });
}

function normalizeSourceRoot(value: string): string | null {
  if (value.trim() === ".") return ".";
  return normalizeRepositoryPath(value);
}

function mergeApplications(
  target: ReconApplication,
  source: ReconApplication,
): ReconApplication {
  return {
    ...target,
    source_roots: normalizeStringSet([
      ...target.source_roots,
      ...source.source_roots,
    ]),
    languages: normalizeStringSet([...target.languages, ...source.languages]),
    frameworks: normalizeStringSet([
      ...target.frameworks,
      ...source.frameworks,
    ]),
    domains: normalizeStringSet([...target.domains, ...source.domains]),
  };
}

function compareSurfaces(a: ReconSurface, b: ReconSurface): number {
  return [a.application_id, a.type, a.method ?? "", a.path_or_name]
    .join(":")
    .localeCompare(
      [b.application_id, b.type, b.method ?? "", b.path_or_name].join(":"),
    );
}

function compareResources(a: ReconResource, b: ReconResource): number {
  return [a.application_id, a.type, a.provider, a.identifier]
    .join(":")
    .localeCompare(
      [b.application_id, b.type, b.provider, b.identifier].join(":"),
    );
}
