import path from "node:path";
import type { z } from "zod";
import type { AIAuthConfig, AIModel, OpenAIReasoningEffort } from "../ai";
import type { AgentEventBus } from "../eventBus";
import { newSessionId } from "../id/id";
import { type SessionInfo, sessions } from "../session";
import { runWithBoundedConcurrency } from "../utils/concurrency";
import {
  defaultReconAgentRunners,
  RECON_MODEL_OUTPUT_LIMITS,
  type ReconAgentRunners,
  type ReconModelRuntime,
} from "./agents";
import {
  createReconArtifacts,
  ObservationJournal,
  type ReconArtifactPaths,
  readJsonArtifact,
  writeInventoryArtifact,
  writeJsonArtifact,
} from "./artifacts";
import {
  createReconAbortSignal,
  DEFAULT_RECON_BUDGET,
  ReconBudget,
  ReconBudgetExceededError,
  type ReconBudgetLimits,
} from "./budget";
import { createEvidenceBundles, estimateBundleInputTokens } from "./bundles";
import { extractConfigArtifacts } from "./configArtifacts";
import { extractFormalArtifactSurfaces } from "./formalArtifacts";
import { repositoryRunKey } from "./identity";
import { inventoryRepository } from "./inventory";
import { ReconRegistry } from "./registry";
import {
  buildPlannerContext,
  CONFIG_NETWORK_SELECTOR_ID,
  CONFIG_RESOURCE_SELECTOR_ID,
  scanRepositoryForCandidates,
} from "./selectors";
import {
  type EvidenceBundle,
  type ModelResult,
  type PlannerResult,
  PlannerResultSchema,
  ReconciliationResultSchema,
  type ReconMetrics,
  WHITEBOX_RECON_PIPELINE_VERSION,
  WHITEBOX_RECON_SCHEMA,
  type WhiteboxReconResult,
  WhiteboxReconResultSchema,
  WorkerResultSchema,
} from "./types";
import { verifyReconRun, type WorkerExecution } from "./verifier";

const DEFAULT_MODEL: AIModel = "claude-sonnet-4-5";
const DEFAULT_WORKER_CONCURRENCY = 4;
const DEFAULT_MAX_BUNDLES = 32;
const DEFAULT_MAX_BUNDLE_CHARACTERS = 128_000;
const DEFAULT_MAX_CANDIDATES_PER_BUNDLE = 80;
const DEFAULT_MAX_CANDIDATES = 20_000;
const MAX_RECONCILIATION_CHARACTERS = 128_000;

export interface WhiteboxReconInput {
  codebasePath: string;
  model?: AIModel;
  session?: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
  maxConcurrentWorkers?: number;
  maxBundles?: number;
  maxBundleCharacters?: number;
  maxCandidatesPerBundle?: number;
  maxCandidates?: number;
  maxAnalyzableFileBytes?: number;
  budget?: Partial<ReconBudgetLimits>;
}

export interface WhiteboxReconRunResult {
  session: SessionInfo;
  result: WhiteboxReconResult;
  artifacts: ReconArtifactPaths;
}

export function runWhiteboxRecon(
  input: WhiteboxReconInput,
): Promise<WhiteboxReconRunResult> {
  return runWhiteboxReconWithRunners(input, defaultReconAgentRunners);
}

export async function runWhiteboxReconWithRunners(
  input: WhiteboxReconInput,
  runners: ReconAgentRunners,
): Promise<WhiteboxReconRunResult> {
  validateInput(input);
  const startedAt = Date.now();
  const limits = resolveBudget(input.budget);
  const runAbort = createReconAbortSignal(
    input.abortSignal,
    limits.maxDurationMs,
  );
  const workflowId = newSessionId();
  let journal: ObservationJournal | undefined;
  let session: SessionInfo | undefined;

  try {
    const inventory = await inventoryRepository(input.codebasePath, {
      maxAnalyzableBytes: input.maxAnalyzableFileBytes,
      abortSignal: runAbort.signal,
    });
    session =
      input.session ??
      (await sessions.create({
        name: "Whitebox Recon",
        targets: [inventory.repository_root],
        config: {
          mode: "operator",
          agentCwd: inventory.repository_root,
        },
        model: input.model,
        authConfig: input.authConfig,
      }));
    const model = input.model ?? DEFAULT_MODEL;
    const runKey = repositoryRunKey(inventory, {
      pipeline: WHITEBOX_RECON_PIPELINE_VERSION,
      model,
      openAIReasoningEffort: input.openAIReasoningEffort ?? null,
      maxBundleCharacters:
        input.maxBundleCharacters ?? DEFAULT_MAX_BUNDLE_CHARACTERS,
      maxCandidatesPerBundle:
        input.maxCandidatesPerBundle ?? DEFAULT_MAX_CANDIDATES_PER_BUNDLE,
      maxCandidates: input.maxCandidates ?? DEFAULT_MAX_CANDIDATES,
    });
    const artifacts = await createReconArtifacts(session.rootPath, runKey);
    await writeInventoryArtifact(artifacts.inventory, inventory);
    journal = new ObservationJournal(artifacts.observations);
    await journal.append({
      record_type: "run-start",
      run_key: runKey,
      pipeline: WHITEBOX_RECON_PIPELINE_VERSION,
      started_at: new Date(startedAt).toISOString(),
    });
    const registry = new ReconRegistry(inventory.files);
    const budget = new ReconBudget(limits);
    const runtime: ReconModelRuntime = {
      model,
      session,
      authConfig: input.authConfig,
      abortSignal: runAbort.signal,
      openAIReasoningEffort: input.openAIReasoningEffort,
    };
    let agentCalls = 0;
    let agentFailures = 0;
    let bundleCacheHits = 0;
    let plannerCompleted = false;

    input.eventBus?.emit("subagent-spawn", {
      subagentId: workflowId,
      sessionId: workflowId,
      name: "Whitebox Recon v2",
      input: { repositoryRoot: inventory.repository_root, runKey },
      parentSessionId: session.id,
    });
    emitProgress(
      input.eventBus,
      workflowId,
      `Inventory: ${inventory.files.length} files; ${analyzableCount(inventory)} eligible for deterministic selectors.`,
    );

    let planner = await readCachedResult(
      artifacts.planner,
      PlannerResultSchema,
    );
    if (!planner) {
      const seedLedger = await scanRepositoryForCandidates(inventory, [], {
        maxCandidates: input.maxCandidates,
        abortSignal: runAbort.signal,
      });
      const repositoryMap = buildPlannerContext(inventory, seedLedger);
      await writeJsonArtifact(artifacts.repositoryMap, {
        context: repositoryMap,
      });
      try {
        budget.reserve({
          inputTokens: estimateTextTokens(repositoryMap) + 2_000,
          outputTokens: RECON_MODEL_OUTPUT_LIMITS.planner,
        });
        agentCalls++;
        planner = await runners.plan({ runtime, repositoryMap });
        budget.record(planner.usage);
        await writeJsonArtifact(artifacts.planner, planner);
        plannerCompleted = true;
      } catch (error) {
        agentFailures++;
        registry.addUnresolved({
          kind:
            error instanceof ReconBudgetExceededError
              ? "budget"
              : "model-failure",
          summary: "Repository planner did not complete",
          source_files: [],
          reason: errorMessage(error),
        });
        await journal.append({
          record_type: "planner-failure",
          error: errorMessage(error),
        });
      }
    } else {
      plannerCompleted = true;
    }

    const plannerResult: PlannerResult = planner?.result ?? {
      applications: [],
      selectors: [],
      configuration_ownership: [],
      unresolved: [],
    };
    registry.ingestPlanner(plannerResult);
    const formalArtifacts = await extractFormalArtifactSurfaces(
      inventory,
      registry.getApplications(),
      runAbort.signal,
    );
    formalArtifacts.surfaces.forEach((surface) => {
      registry.ingestDeterministicSurface(surface);
    });
    formalArtifacts.unresolved.forEach((item) => {
      registry.addUnresolved(item);
    });
    await writeJsonArtifact(artifacts.formalArtifacts, formalArtifacts);
    const configArtifacts = await extractConfigArtifacts(
      inventory,
      registry.getApplications(),
      plannerResult.configuration_ownership.flatMap((rule) => {
        const applicationId = registry.resolveApplicationReference(
          rule.application_id,
        );
        return applicationId
          ? [{ ...rule, application_id: applicationId }]
          : [];
      }),
      runAbort.signal,
    );
    configArtifacts.surfaces.forEach((surface) => {
      registry.ingestDeterministicSurface(surface);
    });
    configArtifacts.resources.forEach((resource) => {
      registry.ingestDeterministicResource(resource);
    });
    configArtifacts.domains.forEach((domain) => {
      registry.addApplicationDomain(domain.application_id, domain.domain);
    });
    configArtifacts.unresolved.forEach((item) => {
      registry.addUnresolved(item);
    });
    await writeJsonArtifact(artifacts.configArtifacts, configArtifacts);
    const suppressedBuiltinSelectors = new Map(
      configArtifacts.handled_files.map((filePath) => [
        filePath,
        new Set([CONFIG_NETWORK_SELECTOR_ID, CONFIG_RESOURCE_SELECTOR_ID]),
      ]),
    );
    const ledger = await scanRepositoryForCandidates(
      inventory,
      plannerResult.selectors,
      {
        maxCandidates: input.maxCandidates,
        suppressedBuiltinSelectors,
        abortSignal: runAbort.signal,
      },
    );
    await writeJsonArtifact(artifacts.selectors, ledger.selectors);
    await writeJsonArtifact(artifacts.candidates, ledger);
    const bundles = createEvidenceBundles(
      ledger.candidates,
      registry.getApplications(),
      inventory,
      {
        maxCharacters: input.maxBundleCharacters,
        maxCandidates: input.maxCandidatesPerBundle,
      },
    );
    emitProgress(
      input.eventBus,
      workflowId,
      `Deterministic interfaces/resources: ${formalArtifacts.surfaces.length + configArtifacts.surfaces.length + configArtifacts.resources.length}; selectors: ${ledger.selectors.length}; candidates: ${ledger.candidates.length}; evidence bundles: ${bundles.length}.`,
    );

    const cachedExecutions = new Map<string, WorkerExecution>();
    const missingBundles: EvidenceBundle[] = [];
    for (const bundle of bundles) {
      const cached = await readCachedResult(
        batchArtifactPath(artifacts, bundle.id),
        WorkerResultSchema,
      );
      if (cached?.result.bundle_id === bundle.id) {
        cachedExecutions.set(bundle.id, {
          bundle,
          batch: cached,
          cacheHit: true,
        });
        bundleCacheHits++;
      } else {
        missingBundles.push(bundle);
      }
    }

    let preflightFailure: string | undefined;
    const maxBundles = input.maxBundles ?? DEFAULT_MAX_BUNDLES;
    if (bundles.length > maxBundles) {
      preflightFailure = `bundle-count:${bundles.length}>${maxBundles}`;
    } else if (!runAbort.signal.aborted) {
      const estimatedInput = missingBundles.reduce(
        (total, bundle) => total + estimateBundleInputTokens(bundle),
        0,
      );
      const estimatedOutput =
        missingBundles.length * RECON_MODEL_OUTPUT_LIMITS.worker;
      const budgetState = budget.snapshot();
      if (
        budgetState.modelCalls + missingBundles.length >
        limits.maxModelCalls
      ) {
        preflightFailure = `model-call-limit:${budgetState.modelCalls + missingBundles.length}>${limits.maxModelCalls}`;
      } else if (
        budgetState.estimatedInputTokens + estimatedInput >
        limits.maxInputTokens
      ) {
        preflightFailure = `input-token-limit:${budgetState.estimatedInputTokens + estimatedInput}>${limits.maxInputTokens}`;
      } else if (
        budgetState.reservedOutputTokens + estimatedOutput >
        limits.maxOutputTokens
      ) {
        preflightFailure = `output-token-limit:${budgetState.reservedOutputTokens + estimatedOutput}>${limits.maxOutputTokens}`;
      } else {
        for (const bundle of missingBundles) {
          budget.reserve({
            inputTokens: estimateBundleInputTokens(bundle),
            outputTokens: RECON_MODEL_OUTPUT_LIMITS.worker,
          });
        }
      }
    } else {
      preflightFailure = abortReason(runAbort.signal);
    }

    if (preflightFailure) {
      registry.addUnresolved({
        kind: "budget",
        summary: "Mapping preflight exceeded a hard limit",
        source_files: [],
        reason: preflightFailure,
      });
    }

    const executed = preflightFailure
      ? []
      : await runWithBoundedConcurrency(
          missingBundles,
          input.maxConcurrentWorkers ?? DEFAULT_WORKER_CONCURRENCY,
          async (bundle): Promise<WorkerExecution> => {
            agentCalls++;
            try {
              const batch = await runners.analyzeBundle({
                runtime,
                bundle,
                applications: registry.getApplications(),
              });
              budget.record(batch.usage);
              await writeJsonArtifact(
                batchArtifactPath(artifacts, bundle.id),
                batch,
              );
              await journal?.append({
                record_type: "mapping-batch",
                bundle_id: bundle.id,
                candidates: bundle.candidates.length,
                usage: batch.usage,
              });
              return { bundle, batch, cacheHit: false };
            } catch (error) {
              agentFailures++;
              await journal?.append({
                record_type: "mapping-failure",
                bundle_id: bundle.id,
                error: errorMessage(error),
              });
              return {
                bundle,
                error: errorMessage(error),
                cacheHit: false,
              };
            }
          },
          runAbort.signal,
        );
    const executionById = new Map(cachedExecutions);
    executed.forEach((execution, index) => {
      const bundle = missingBundles[index];
      if (!bundle) return;
      executionById.set(
        bundle.id,
        execution ?? {
          bundle,
          error: abortReason(runAbort.signal) || "mapping-not-started",
          cacheHit: false,
        },
      );
    });
    for (const bundle of missingBundles) {
      if (!executionById.has(bundle.id)) {
        executionById.set(bundle.id, {
          bundle,
          error: preflightFailure ?? "mapping-not-started",
          cacheHit: false,
        });
      }
    }
    const workerExecutions = bundles.map(
      (bundle) =>
        executionById.get(bundle.id) ?? {
          bundle,
          error: "mapping-result-missing",
          cacheHit: false,
        },
    );
    for (const execution of workerExecutions) {
      if (execution.batch) {
        registry.ingestWorker(execution.batch.result, execution.bundle);
      }
    }

    const allMappingsCompleted = workerExecutions.every(
      (execution) => execution.batch,
    );
    const reconciliationRequired =
      allMappingsCompleted && registry.needsReconciliation();
    let reconciliationCompleted = !reconciliationRequired;
    if (reconciliationRequired) {
      const snapshot = registry.reconciliationSnapshot();
      await writeJsonArtifact(artifacts.reconciliationInput, snapshot);
      let reconciliation = await readCachedResult(
        artifacts.reconciliation,
        ReconciliationResultSchema,
      );
      if (!reconciliation) {
        const snapshotCharacters = JSON.stringify(snapshot).length;
        if (snapshotCharacters > MAX_RECONCILIATION_CHARACTERS) {
          registry.addUnresolved({
            kind: "budget",
            summary: "Reconciliation input exceeds its hard size limit",
            source_files: [],
            reason: `reconciliation-characters:${snapshotCharacters}>${MAX_RECONCILIATION_CHARACTERS}`,
          });
        } else {
          try {
            budget.reserve({
              inputTokens: estimateTextTokens(JSON.stringify(snapshot)) + 2_000,
              outputTokens: RECON_MODEL_OUTPUT_LIMITS.reducer,
            });
            agentCalls++;
            reconciliation = await runners.reconcile({ runtime, snapshot });
            budget.record(reconciliation.usage);
            await writeJsonArtifact(artifacts.reconciliation, reconciliation);
          } catch (error) {
            agentFailures++;
            registry.addUnresolved({
              kind:
                error instanceof ReconBudgetExceededError
                  ? "budget"
                  : "model-failure",
              summary: "Canonical reconciliation failed",
              source_files: [],
              reason: errorMessage(error),
            });
          }
        }
      }
      if (reconciliation) {
        registry.applyReconciliation(reconciliation.result);
        reconciliationCompleted = true;
      }
    }

    const actualUsage = budget.snapshot();
    if (actualUsage.actualInputTokens > limits.maxInputTokens) {
      registry.addUnresolved({
        kind: "budget",
        summary: "Provider-reported input usage exceeded the run limit",
        source_files: [],
        reason: `input-tokens:${actualUsage.actualInputTokens}>${limits.maxInputTokens}`,
      });
    }
    if (actualUsage.actualOutputTokens > limits.maxOutputTokens) {
      registry.addUnresolved({
        kind: "budget",
        summary: "Provider-reported output usage exceeded the run limit",
        source_files: [],
        reason: `output-tokens:${actualUsage.actualOutputTokens}>${limits.maxOutputTokens}`,
      });
    }

    const verification = verifyReconRun({
      inventory,
      ledger,
      bundles,
      workers: workerExecutions,
      registry,
      plannerCompleted,
      reconciliationRequired,
      reconciliationCompleted,
    });
    const recordMetrics = registry.getCandidateMetrics();
    const budgetMetrics = budget.snapshot();
    const metrics: ReconMetrics = {
      duration_ms: Date.now() - startedAt,
      files_total: inventory.files.length,
      files_relevant: analyzableCount(inventory),
      files_reviewed: verification.filesReviewed,
      selectors_total: ledger.selectors.length,
      selectors_completed:
        ledger.errors.length === 0 ? ledger.selectors.length : 0,
      shards_total: bundles.length,
      shards_completed: verification.bundlesCompleted,
      bundle_cache_hits: bundleCacheHits,
      candidates_total: ledger.candidates.length,
      candidates_accepted: verification.candidates.accepted,
      candidates_persisted: verification.candidates.persisted,
      candidates_duplicate: verification.candidates.duplicate,
      candidates_rejected: verification.candidates.rejected,
      candidates_unresolved: verification.candidates.unresolved,
      records_accepted: recordMetrics.accepted,
      records_persisted: recordMetrics.persisted,
      agent_calls: agentCalls,
      agent_failures: agentFailures,
      tokens_in: budgetMetrics.actualInputTokens,
      tokens_out: budgetMetrics.actualOutputTokens,
      estimated_tokens_in: budgetMetrics.estimatedInputTokens,
    };
    const result = WhiteboxReconResultSchema.parse({
      $schema: WHITEBOX_RECON_SCHEMA,
      status: verification.status,
      repository_root: inventory.repository_root,
      applications: registry.getApplications(),
      surfaces: registry.getSurfaces(),
      resources: registry.getResources(),
      unresolved: registry.getUnresolved(),
      metrics,
    });
    await writeJsonArtifact(
      artifacts.registry,
      registry.reconciliationSnapshot(),
    );
    await writeJsonArtifact(artifacts.metrics, metrics);
    await writeJsonArtifact(artifacts.result, result);
    await journal.append({
      record_type: "run-complete",
      status: result.status,
      metrics,
    });
    await journal.flush();
    input.eventBus?.emit("subagent-complete", {
      subagentId: workflowId,
      sessionId: workflowId,
      status: "completed",
      parentSessionId: session.id,
    });
    return { session, result, artifacts };
  } catch (error) {
    await journal?.append({
      record_type: "run-failure",
      error: errorMessage(error),
    });
    await journal?.flush().catch(() => undefined);
    if (session) {
      input.eventBus?.emit("subagent-complete", {
        subagentId: workflowId,
        sessionId: workflowId,
        status: "failed",
        parentSessionId: session.id,
      });
    }
    throw error;
  } finally {
    runAbort.dispose();
  }
}

function resolveBudget(
  overrides: Partial<ReconBudgetLimits> | undefined,
): ReconBudgetLimits {
  const resolved = { ...DEFAULT_RECON_BUDGET, ...overrides };
  assertPositiveInteger("budget.maxModelCalls", resolved.maxModelCalls, 64);
  assertPositiveInteger(
    "budget.maxInputTokens",
    resolved.maxInputTokens,
    5_000_000,
  );
  assertPositiveInteger(
    "budget.maxOutputTokens",
    resolved.maxOutputTokens,
    500_000,
  );
  assertPositiveInteger(
    "budget.maxDurationMs",
    resolved.maxDurationMs,
    2 * 60 * 60 * 1_000,
  );
  return resolved;
}

function validateInput(input: WhiteboxReconInput): void {
  assertPositiveInteger("maxConcurrentWorkers", input.maxConcurrentWorkers, 4);
  assertPositiveInteger("maxBundles", input.maxBundles, 64);
  assertPositiveInteger(
    "maxBundleCharacters",
    input.maxBundleCharacters,
    256_000,
  );
  assertPositiveInteger(
    "maxCandidatesPerBundle",
    input.maxCandidatesPerBundle,
    200,
  );
  assertPositiveInteger("maxCandidates", input.maxCandidates, 50_000);
  assertPositiveInteger(
    "maxAnalyzableFileBytes",
    input.maxAnalyzableFileBytes,
    10_000_000,
  );
}

async function readCachedResult<TResult>(
  artifactPath: string,
  schema: z.ZodType<TResult>,
): Promise<ModelResult<TResult> | null> {
  const value = await readJsonArtifact(artifactPath);
  if (!value || typeof value !== "object") return null;
  const result = schema.safeParse("result" in value ? value.result : undefined);
  const usage =
    "usage" in value && value.usage && typeof value.usage === "object"
      ? value.usage
      : undefined;
  if (
    !result.success ||
    !usage ||
    !("input_tokens" in usage) ||
    !("output_tokens" in usage) ||
    typeof usage.input_tokens !== "number" ||
    typeof usage.output_tokens !== "number"
  ) {
    return null;
  }
  return {
    result: result.data,
    usage: {
      input_tokens: usage.input_tokens,
      output_tokens: usage.output_tokens,
    },
  };
}

function batchArtifactPath(
  artifacts: ReconArtifactPaths,
  bundleId: string,
): string {
  return path.join(artifacts.workers, `${bundleId}.json`);
}

function estimateTextTokens(value: string): number {
  return Math.ceil(value.length / 3);
}

function analyzableCount(inventory: {
  files: Array<{ relevance: string }>;
}): number {
  return inventory.files.filter((file) => file.relevance === "analyze").length;
}

function emitProgress(
  eventBus: AgentEventBus | undefined,
  subagentId: string,
  message: string,
): void {
  eventBus?.emit("command-output", {
    data: `${message}\n`,
    subagentId,
  });
}

function abortReason(signal: AbortSignal): string {
  if (!signal.aborted) return "";
  return signal.reason instanceof Error
    ? signal.reason.message
    : String(signal.reason ?? "aborted");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function assertPositiveInteger(
  name: string,
  value: number | undefined,
  maximum?: number,
): void {
  if (
    value !== undefined &&
    (!Number.isInteger(value) ||
      value < 1 ||
      (maximum !== undefined && value > maximum))
  ) {
    throw new Error(
      `${name} must be a positive integer${maximum ? ` no greater than ${maximum}` : ""}`,
    );
  }
}
