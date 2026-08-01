import type { ReconRegistry } from "./registry";
import type {
  CandidateLedger,
  EvidenceBundle,
  ModelResult,
  RepositoryInventory,
  UnresolvedItem,
  WorkerResult,
} from "./types";

export interface WorkerExecution {
  bundle: EvidenceBundle;
  batch?: ModelResult<WorkerResult>;
  error?: string;
  cacheHit: boolean;
}

export interface VerificationInput {
  inventory: RepositoryInventory;
  ledger: CandidateLedger;
  bundles: EvidenceBundle[];
  workers: WorkerExecution[];
  registry: ReconRegistry;
  plannerCompleted: boolean;
  reconciliationRequired: boolean;
  reconciliationCompleted: boolean;
}

export interface VerificationResult {
  status: "complete" | "incomplete";
  filesReviewed: number;
  bundlesCompleted: number;
  issues: UnresolvedItem[];
  candidates: {
    accepted: number;
    persisted: number;
    duplicate: number;
    rejected: number;
    unresolved: number;
  };
}

export function verifyReconRun(input: VerificationInput): VerificationResult {
  const issues: UnresolvedItem[] = [...input.ledger.errors];
  const analyzable = input.inventory.files.filter(
    (file) => file.relevance === "analyze",
  );
  const scansByPath = new Map<string, number>();
  for (const scan of input.ledger.files) {
    scansByPath.set(scan.path, (scansByPath.get(scan.path) ?? 0) + 1);
    if (scan.status === "unresolved") {
      issues.push({
        kind: "selector",
        summary: `Selector scan incomplete for ${scan.path}`,
        source_files: [scan.path],
        reason: scan.reason ?? "selector-scan-unresolved",
      });
    }
  }
  for (const file of analyzable) {
    const count = scansByPath.get(file.path) ?? 0;
    if (count !== 1) {
      issues.push({
        kind: "selector",
        summary: `Invalid selector disposition for ${file.path}`,
        source_files: [file.path],
        reason:
          count === 0 ? "file-not-scanned" : `file-scanned-${count}-times`,
      });
    }
  }
  for (const file of input.inventory.files.filter(
    (candidate) => candidate.relevance === "unresolved",
  )) {
    issues.push({
      kind: "inventory",
      summary: `Inventory could not analyze ${file.path}`,
      source_files: [file.path],
      reason: file.reason ?? "inventory-file-unresolved",
    });
  }
  for (const directory of input.inventory.excluded_directories.filter(
    (candidate) => candidate.reason.startsWith("unreadable-directory:"),
  )) {
    issues.push({
      kind: "inventory",
      summary: `Inventory could not enumerate ${directory.path}`,
      source_files: [directory.path],
      reason: directory.reason,
    });
  }
  if (!input.plannerCompleted) {
    issues.push({
      kind: "model-failure",
      summary: "Repository planning did not complete",
      source_files: [],
      reason: "planner-failed",
    });
  }

  const assignmentCounts = new Map<string, number>();
  for (const bundle of input.bundles) {
    for (const candidate of bundle.candidates) {
      assignmentCounts.set(
        candidate.id,
        (assignmentCounts.get(candidate.id) ?? 0) + 1,
      );
    }
  }
  for (const candidate of input.ledger.candidates) {
    const count = assignmentCounts.get(candidate.id) ?? 0;
    if (count !== 1) {
      issues.push({
        kind: "candidate",
        summary: `Invalid bundle assignment for ${candidate.id}`,
        source_files: [candidate.path],
        reason:
          count === 0
            ? "candidate-not-assigned"
            : `candidate-assigned-${count}-times`,
      });
    }
  }

  let bundlesCompleted = 0;
  const dispositionCounts = {
    accepted: 0,
    persisted: 0,
    duplicate: 0,
    rejected: 0,
    unresolved: 0,
  };
  const acceptedCandidateIds = new Set<string>();
  for (const execution of input.workers) {
    if (!execution.batch) {
      issues.push({
        kind: "model-failure",
        summary: `Mapping failed for ${execution.bundle.id}`,
        source_files: sourceFiles(execution.bundle),
        reason: execution.error ?? "mapping-result-missing",
      });
      continue;
    }
    bundlesCompleted++;
    const result = execution.batch.result;
    if (result.bundle_id !== execution.bundle.id) {
      issues.push({
        kind: "batch",
        summary: `Mapper returned the wrong bundle id for ${execution.bundle.id}`,
        source_files: sourceFiles(execution.bundle),
        reason: `returned:${result.bundle_id}`,
      });
    }
    const assigned = new Set(
      execution.bundle.candidates.map((candidate) => candidate.id),
    );
    const reviewCounts = new Map<string, number>();
    for (const review of result.candidate_reviews) {
      reviewCounts.set(
        review.candidate_id,
        (reviewCounts.get(review.candidate_id) ?? 0) + 1,
      );
      if (!assigned.has(review.candidate_id)) {
        issues.push({
          kind: "candidate",
          summary: `Mapper reviewed an out-of-bundle candidate`,
          source_files: sourceFiles(execution.bundle),
          reason: `unexpected-candidate:${review.candidate_id}`,
        });
        continue;
      }
      dispositionCounts[review.disposition]++;
      if (review.disposition === "accepted") {
        acceptedCandidateIds.add(review.candidate_id);
      } else if (review.disposition === "unresolved") {
        issues.push({
          kind: "candidate",
          summary: `Candidate remains unresolved: ${review.candidate_id}`,
          source_files: candidateFiles(execution.bundle, review.candidate_id),
          reason: review.reason ?? "mapper-candidate-unresolved",
        });
      }
    }
    for (const candidate of execution.bundle.candidates) {
      const count = reviewCounts.get(candidate.id) ?? 0;
      if (count !== 1) {
        issues.push({
          kind: "candidate",
          summary: `Mapper did not disposition ${candidate.id} exactly once`,
          source_files: [candidate.path],
          reason:
            count === 0
              ? "candidate-review-missing"
              : `candidate-reviewed-${count}-times`,
        });
      }
    }
  }

  const persistedCandidateIds = input.registry.getPersistedCandidateIds();
  for (const candidateId of acceptedCandidateIds) {
    if (persistedCandidateIds.has(candidateId)) {
      dispositionCounts.persisted++;
    } else {
      const candidate = input.ledger.candidates.find(
        (item) => item.id === candidateId,
      );
      issues.push({
        kind: "conflict",
        summary: `Accepted candidate was not persisted: ${candidateId}`,
        source_files: candidate ? [candidate.path] : [],
        reason: "accepted-candidate-not-persisted",
      });
    }
  }

  if (input.reconciliationRequired && !input.reconciliationCompleted) {
    issues.push({
      kind: "model-failure",
      summary: "Required canonical reconciliation did not complete",
      source_files: [],
      reason: "reconciliation-failed",
    });
  }
  if (analyzable.length > 0 && input.registry.getApplications().length === 0) {
    issues.push({
      kind: "application",
      summary: "No deployable application or service was identified",
      source_files: [],
      reason: "application-inventory-empty",
    });
  }
  const recordMetrics = input.registry.getCandidateMetrics();
  if (recordMetrics.accepted !== recordMetrics.persisted) {
    issues.push({
      kind: "conflict",
      summary: "Accepted records do not match persisted records",
      source_files: [],
      reason: `accepted:${recordMetrics.accepted};persisted:${recordMetrics.persisted}`,
    });
  }

  for (const issue of issues) input.registry.addUnresolved(issue);
  const status =
    issues.length === 0 && input.registry.getUnresolved().length === 0
      ? "complete"
      : "incomplete";
  return {
    status,
    filesReviewed: input.ledger.files.filter(
      (scan) => scan.status !== "unresolved",
    ).length,
    bundlesCompleted,
    issues,
    candidates: dispositionCounts,
  };
}

function sourceFiles(bundle: EvidenceBundle): string[] {
  return [
    ...new Set(bundle.candidates.map((candidate) => candidate.path)),
  ].sort();
}

function candidateFiles(bundle: EvidenceBundle, candidateId: string): string[] {
  const candidate = bundle.candidates.find((item) => item.id === candidateId);
  return candidate ? [candidate.path] : [];
}
