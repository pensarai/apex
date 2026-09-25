import { createHash, randomUUID } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import type { ModelMessage } from "ai";
import type { SwarmTarget } from "../session/persistence";
import type {
  EngagementMission,
  EngagementMissionCoverage,
  EngagementMissionState,
  EngagementModelConfig,
} from "./engagementMissions";
import type {
  DeploymentPreflightArtifact,
  DeploymentPrerequisiteDisposition,
} from "./engagementPreflight";
import type { PersistedEvidenceObservation } from "./fastStrikeEvidence";

export type CoverageStatus =
  | "pending"
  | "assigned"
  | "running"
  | "needs-lead"
  | "impact-proven"
  | "exhausted"
  | "blocked";
export type ServiceCoverageStatus =
  | "pending"
  | "running"
  | "explored"
  | "blocked";
export type ChainExploreStatus =
  | "pending"
  | "running"
  | "impact-proven"
  | "exhausted"
  | "blocked";
export type EngagementWorkerMode =
  | "targeted"
  | "fast-strike"
  | "grouped"
  | "explore"
  | "chain";

export interface EngagementService {
  id: string;
  origin: string;
  targets: string[];
  baselineStatus: ServiceCoverageStatus;
  summary?: string;
}

export interface EngagementObjective {
  id: string;
  text: string;
  relevantServiceIds: string[];
}

export interface EngagementTargetRecord {
  id: string;
  target: string;
  serviceId: string;
  objectiveIds: string[];
}

export interface ObjectiveCoverage {
  targetId: string;
  objectiveId: string;
  serviceId: string;
  status: CoverageStatus;
  attempts: number;
  workerId?: string;
  missionId?: string;
  summary?: string;
  evidence: string[];
}

export interface ImpactProof {
  id: string;
  description: string;
  objectiveIds: string[];
  serviceIds: string[];
  targetIds: string[];
  findingIds: string[];
  capabilityIds: string[];
  artifactPaths: string[];
  observationRefs: string[];
  createdAt: string;
}

export interface EngagementCapability {
  id: string;
  label: string;
  description: string;
  status: "candidate" | "confirmed" | "consumed" | "blocked";
  serviceIds: string[];
  targetIds: string[];
  objectiveIds: string[];
  evidence: string[];
  nextSteps: string[];
  updatedAt: string;
}

export type EngagementChainStatus = Extract<
  ChainExploreStatus,
  "impact-proven" | "exhausted" | "blocked"
>;

export interface EngagementChainStep {
  id: string;
  title: string;
  description: string;
  findingIds: string[];
  capabilityIds: string[];
  impactProofIds: string[];
  objectiveIds: string[];
  serviceIds: string[];
  targetIds: string[];
  artifactPaths: string[];
  observationRefs: string[];
  evidence: string[];
}

/** A composed attack path or a materially useful terminal chain attempt. */
export interface EngagementChain {
  id: string;
  title: string;
  status: EngagementChainStatus;
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
  impact: string;
  remediation?: string;
  findingIds: string[];
  capabilityIds: string[];
  impactProofIds: string[];
  objectiveIds: string[];
  serviceIds: string[];
  targetIds: string[];
  evidence: string[];
  steps: EngagementChainStep[];
  evidenceQuality: "verified" | "legacy-incomplete";
  blocker?: string;
  createdAt: string;
  updatedAt: string;
}

export interface EngagementWorkerRecord {
  id: string;
  mission: string;
  mode: EngagementWorkerMode;
  serviceIds: string[];
  targetIds: string[];
  objectiveIds: string[];
  capabilityIds: string[];
  actorIds?: string[];
  model?: EngagementModelConfig;
  status: "queued" | "running" | "completed" | "failed";
  summary?: string;
  startedAt?: string;
  completedAt?: string;
}

export interface EngagementActorRecord {
  id: string;
  label: string;
  role: string;
  status: "ready" | "unavailable";
  credentialIds: string[];
  targetIds: string[];
  serviceIds: string[];
  provenance: "operator" | "authentication" | "prior-session";
  verificationSummary: string;
  verifiedAt: string;
  unavailableReason?: string;
}

export interface EngagementActorState {
  status: "pending" | "complete";
  actors: EngagementActorRecord[];
}

export interface EngagementFindingConsolidationState {
  completedAt: string;
  sourceFindingCount: number;
  canonicalFindingCount: number;
  aliasCount: number;
  rootCauseGroupCount: number;
}

export interface EngagementState {
  version: 4;
  contextReads?: Record<
    string,
    {
      status: "read" | "unavailable";
      version?: string;
      complete: boolean;
      hasProductContext: boolean;
    }
  >;
  concurrency?: number;
  missions?: EngagementMissionState;
  models?: {
    lead: EngagementModelConfig;
    worker: EngagementModelConfig;
    judge?: EngagementModelConfig;
  };
  rootTarget: string;
  operatorContext?: string;
  targets: EngagementTargetRecord[];
  services: EngagementService[];
  objectives: EngagementObjective[];
  coverage: ObjectiveCoverage[];
  capabilities: EngagementCapability[];
  impactProofs: ImpactProof[];
  evidenceObservations: PersistedEvidenceObservation[];
  chains: EngagementChain[];
  workers: EngagementWorkerRecord[];
  actors?: EngagementActorState;
  deploymentPreflight?: DeploymentPreflightArtifact;
  findingConsolidation?: EngagementFindingConsolidationState;
  chainExplore: {
    status: ChainExploreStatus;
    summary?: string;
    evidence: string[];
  };
  updatedAt: string;
}

export interface EngagementCompletion {
  complete: boolean;
  missingObjectiveIds: string[];
  missingCoverageCellIds: string[];
  missingServiceIds: string[];
  unresolvedCapabilityIds: string[];
  chainExplorePending: boolean;
  missionPlanningPending: boolean;
  activeMissionIds: string[];
  activeWorkerIds: string[];
  coverageSummary: {
    tested: number;
    blocked: number;
    untested: number;
    total: number;
  };
}

/** Compact durable state embedded in coordination tool results for host resume. */
export interface EngagementCheckpoint {
  version: 2 | 3 | 4;
  contextReads?: EngagementState["contextReads"];
  concurrency?: number;
  missions?: EngagementMissionState;
  models?: {
    lead: EngagementModelConfig;
    worker: EngagementModelConfig;
    judge?: EngagementModelConfig;
  };
  targets?: EngagementTargetRecord[];
  objectives: EngagementObjective[];
  services: Array<Pick<EngagementService, "id" | "baselineStatus" | "summary">>;
  coverage: ObjectiveCoverage[];
  capabilities: EngagementCapability[];
  impactProofs: ImpactProof[];
  evidenceObservations?: PersistedEvidenceObservation[];
  chains?: EngagementChain[];
  workers: EngagementWorkerRecord[];
  actors?: EngagementActorState;
  deploymentPreflight?: DeploymentPreflightArtifact;
  findingConsolidation?: EngagementFindingConsolidationState;
  chainExplore: EngagementState["chainExplore"];
  updatedAt: string;
}

export type AgentMailboxMessageType = "MESSAGE" | "FINAL_ANSWER";

export interface AgentMailboxMessage {
  id: string;
  sequence: number;
  timestamp: string;
  type: AgentMailboxMessageType;
  recipientAgentId: string;
  senderAgentId: string;
  taskName: string;
  payload: string;
  status?: "completed" | "failed";
}

const TERMINAL_COVERAGE = new Set<CoverageStatus>([
  "impact-proven",
  "exhausted",
  "blocked",
]);

export const DEFAULT_ENGAGEMENT_BASELINE_OBJECTIVE =
  "Perform bounded baseline exploration for net-new exploitable vulnerabilities.";
const TERMINAL_SERVICE = new Set<ServiceCoverageStatus>([
  "explored",
  "blocked",
]);
const TERMINAL_CHAIN = new Set<ChainExploreStatus>([
  "impact-proven",
  "exhausted",
  "blocked",
]);

function unique(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function stableId(prefix: string, value: string): string {
  return `${prefix}_${createHash("sha256").update(value).digest("hex").slice(0, 12)}`;
}

export function engagementCoverageCellId(
  targetId: string,
  objectiveId: string,
): string {
  return `${targetId}:${objectiveId}`;
}

function targetOrigin(target: string): string {
  try {
    return new URL(target).origin;
  } catch {
    return target.trim().replace(/\/$/, "");
  }
}

function atomicWrite(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  renameSync(temporaryPath, path);
}

export function buildEngagementState(
  rootTarget: string,
  targets: SwarmTarget[],
  operatorContext?: string,
): EngagementState {
  const serviceByOrigin = new Map<string, EngagementService>();
  const objectiveByText = new Map<string, EngagementObjective>();
  const targetRecords: EngagementTargetRecord[] = [];

  for (const target of targets) {
    const origin = targetOrigin(target.target);
    const service = serviceByOrigin.get(origin) ?? {
      id: stableId("svc", origin),
      origin,
      targets: [],
      baselineStatus: "pending" as const,
    };
    service.targets = unique([...service.targets, target.target]);
    serviceByOrigin.set(origin, service);

    const targetId = target.id ?? stableId("target", target.target);
    const targetObjectives = target.objectives.some((text) => text.trim())
      ? target.objectives
      : [DEFAULT_ENGAGEMENT_BASELINE_OBJECTIVE];
    const objectiveIds: string[] = [];
    for (const text of targetObjectives) {
      const normalized = text.trim();
      if (!normalized) continue;
      const objective = objectiveByText.get(normalized) ?? {
        id: stableId("obj", normalized),
        text: normalized,
        relevantServiceIds: [],
      };
      objective.relevantServiceIds = unique([
        ...objective.relevantServiceIds,
        service.id,
      ]);
      objectiveByText.set(normalized, objective);
      objectiveIds.push(objective.id);
    }
    targetRecords.push({
      id: targetId,
      target: target.target,
      serviceId: service.id,
      objectiveIds: unique(objectiveIds),
    });
  }

  const services = [...serviceByOrigin.values()];
  const objectives = [...objectiveByText.values()];
  const coverage = targetRecords.flatMap((target) =>
    target.objectiveIds.map((objectiveId) => ({
      targetId: target.id,
      objectiveId,
      serviceId: target.serviceId,
      status: "pending" as const,
      attempts: 0,
      evidence: [],
    })),
  );
  return {
    version: 4,
    rootTarget,
    operatorContext,
    targets: targetRecords,
    services,
    objectives,
    coverage,
    capabilities: [],
    impactProofs: [],
    evidenceObservations: [],
    chains: [],
    workers: [],
    chainExplore: { status: "pending", evidence: [] },
    updatedAt: new Date().toISOString(),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseToolOutput(output: unknown): unknown {
  if (isRecord(output) && "value" in output)
    return parseToolOutput(output.value);
  if (typeof output !== "string") return output;
  try {
    return JSON.parse(output) as unknown;
  } catch {
    return undefined;
  }
}

interface LegacyEngagementCheckpoint
  extends Omit<
    EngagementCheckpoint,
    | "version"
    | "objectives"
    | "coverage"
    | "capabilities"
    | "impactProofs"
    | "workers"
  > {
  version: 1;
  objectives?: EngagementObjective[];
  coverage: Array<Omit<ObjectiveCoverage, "targetId" | "attempts">>;
  capabilities: Array<Omit<EngagementCapability, "targetIds">>;
  impactProofs: Array<Omit<ImpactProof, "targetIds">>;
  workers: Array<Omit<EngagementWorkerRecord, "targetIds" | "capabilityIds">>;
}

type RestorableEngagementCheckpoint =
  | EngagementCheckpoint
  | LegacyEngagementCheckpoint;

function isEngagementCheckpoint(
  value: unknown,
): value is RestorableEngagementCheckpoint {
  return (
    isRecord(value) &&
    (value.version === 1 ||
      value.version === 2 ||
      value.version === 3 ||
      value.version === 4) &&
    (value.version === 1 || Array.isArray(value.objectives)) &&
    Array.isArray(value.services) &&
    Array.isArray(value.coverage) &&
    Array.isArray(value.capabilities) &&
    Array.isArray(value.impactProofs) &&
    Array.isArray(value.workers) &&
    isRecord(value.chainExplore) &&
    typeof value.updatedAt === "string"
  );
}

function isEngagementState(value: unknown): value is EngagementState {
  const record = value as Record<string, unknown>;
  return (
    isEngagementCheckpoint(value) &&
    (value.version === 2 || value.version === 3 || value.version === 4) &&
    typeof record.rootTarget === "string" &&
    Array.isArray(record.objectives)
  );
}

function normalizeChains(
  chains: readonly EngagementChain[],
): EngagementChain[] {
  return chains.map((chain) => {
    const legacySteps = (chain.steps ?? []) as Array<
      Partial<EngagementChainStep> & {
        title?: string;
        description?: string;
      }
    >;
    const legacyIncomplete =
      chain.evidenceQuality === undefined ||
      legacySteps.length === 0 ||
      legacySteps.some(
        (step) =>
          !step.id ||
          !step.title?.trim() ||
          !step.description?.trim() ||
          unique([
            ...(step.findingIds ?? []),
            ...(step.capabilityIds ?? []),
            ...(step.impactProofIds ?? []),
            ...(step.artifactPaths ?? []),
            ...(step.observationRefs ?? []),
            ...(step.evidence ?? []),
          ]).length === 0,
      );
    return {
      ...structuredClone(chain),
      evidenceQuality: legacyIncomplete
        ? "legacy-incomplete"
        : chain.evidenceQuality,
      steps: legacySteps.map((step, index) => ({
        id:
          step.id ??
          stableId(
            "step",
            `${chain.id}:${index}:${step.title ?? "legacy"}:${step.description ?? ""}`,
          ),
        title: step.title?.trim() ?? `Legacy step ${index + 1}`,
        description: step.description?.trim() ?? "Legacy chain step",
        findingIds: unique(step.findingIds ?? []),
        capabilityIds: unique(step.capabilityIds ?? []),
        impactProofIds: unique(step.impactProofIds ?? []),
        objectiveIds: unique(step.objectiveIds ?? []),
        serviceIds: unique(step.serviceIds ?? []),
        targetIds: unique(step.targetIds ?? []),
        artifactPaths: unique(step.artifactPaths ?? []),
        observationRefs: unique(step.observationRefs ?? []),
        evidence: unique(step.evidence ?? []),
      })),
    };
  });
}

function evidenceObservationKey(
  observation: PersistedEvidenceObservation,
): string {
  return [
    observation.toolCallId,
    observation.toolName,
    observation.subagentId ?? "",
    observation.sessionId ?? "",
    observation.failed ? "failed" : "succeeded",
  ].join("\u0000");
}

function normalizeEvidenceObservations(
  observations: readonly PersistedEvidenceObservation[],
): PersistedEvidenceObservation[] {
  const uniqueObservations = new Map<string, PersistedEvidenceObservation>();
  for (const observation of observations) {
    uniqueObservations.set(
      evidenceObservationKey(observation),
      structuredClone(observation),
    );
  }
  return [...uniqueObservations.values()];
}

function applyCheckpoint(
  seed: EngagementState,
  checkpoint: RestorableEngagementCheckpoint,
): EngagementState {
  const serviceUpdates = new Map(
    checkpoint.services.map((service) => [service.id, service]),
  );
  const isLegacy = checkpoint.version === 1;
  return {
    ...structuredClone(seed),
    version: 4,
    concurrency: checkpoint.concurrency,
    contextReads:
      "contextReads" in checkpoint
        ? structuredClone(checkpoint.contextReads)
        : undefined,
    missions: structuredClone(checkpoint.missions),
    models: structuredClone(checkpoint.models),
    services: seed.services.map((service) => ({
      ...service,
      ...serviceUpdates.get(service.id),
    })),
    targets:
      !isLegacy && checkpoint.targets
        ? structuredClone(checkpoint.targets)
        : structuredClone(seed.targets),
    objectives: checkpoint.objectives
      ? structuredClone(checkpoint.objectives)
      : structuredClone(seed.objectives),
    coverage: isLegacy
      ? structuredClone(seed.coverage)
      : structuredClone(checkpoint.coverage),
    capabilities: checkpoint.capabilities.map((capability) => ({
      ...structuredClone(capability),
      targetIds: "targetIds" in capability ? capability.targetIds : [],
    })),
    impactProofs: checkpoint.impactProofs.map((proof) => ({
      ...structuredClone(proof),
      targetIds: "targetIds" in proof ? proof.targetIds : [],
    })),
    evidenceObservations: normalizeEvidenceObservations([
      ...seed.evidenceObservations,
      ...(checkpoint.evidenceObservations ?? []),
    ]),
    chains: normalizeChains(checkpoint.chains ?? []),
    workers: checkpoint.workers.map((worker) => ({
      ...structuredClone(worker),
      targetIds: "targetIds" in worker ? worker.targetIds : [],
      capabilityIds: "capabilityIds" in worker ? worker.capabilityIds : [],
      actorIds: "actorIds" in worker ? worker.actorIds : undefined,
    })),
    actors:
      "actors" in checkpoint ? structuredClone(checkpoint.actors) : undefined,
    deploymentPreflight:
      "deploymentPreflight" in checkpoint
        ? structuredClone(checkpoint.deploymentPreflight)
        : undefined,
    findingConsolidation:
      "findingConsolidation" in checkpoint
        ? structuredClone(checkpoint.findingConsolidation)
        : undefined,
    chainExplore: structuredClone(checkpoint.chainExplore),
    updatedAt: checkpoint.updatedAt,
  };
}

/** Restore the newest Console-persisted coordination checkpoint, if present. */
export function restoreEngagementState(
  seed: EngagementState,
  messages: readonly ModelMessage[] | undefined,
): EngagementState {
  if (!messages) return seed;
  for (
    let messageIndex = messages.length - 1;
    messageIndex >= 0;
    messageIndex--
  ) {
    const content = messages[messageIndex]?.content;
    if (!Array.isArray(content)) continue;
    for (let partIndex = content.length - 1; partIndex >= 0; partIndex--) {
      const part = content[partIndex] as Record<string, unknown>;
      if (part.type !== "tool-result") continue;
      const result = parseToolOutput(part.output);
      if (!isRecord(result)) continue;
      if (isEngagementCheckpoint(result.checkpoint)) {
        return applyCheckpoint(seed, result.checkpoint);
      }
      if (isEngagementState(result.state)) {
        return applyCheckpoint(seed, result.state);
      }
    }
  }
  return seed;
}

/** Single-writer, persisted engagement graph and coverage contract. */
export class EngagementStore {
  private readonly statePath: string;
  private readonly evidencePath: string;
  private state: EngagementState;

  static open(sessionRootPath: string, seed: EngagementState): EngagementStore {
    const statePath = join(sessionRootPath, "coordination", "engagement.json");
    if (!existsSync(statePath)) return new EngagementStore(statePath, seed);
    const parsed = JSON.parse(readFileSync(statePath, "utf8")) as unknown;
    if (!isEngagementCheckpoint(parsed)) {
      throw new Error(
        `Unsupported engagement state version: ${isRecord(parsed) ? String(parsed.version) : "unknown"}`,
      );
    }
    return new EngagementStore(statePath, applyCheckpoint(seed, parsed));
  }

  private constructor(statePath: string, state: EngagementState) {
    this.statePath = statePath;
    this.evidencePath = join(dirname(statePath), "engagement-evidence.jsonl");
    this.state = structuredClone(state);
    if (existsSync(this.evidencePath)) {
      const persisted = readFileSync(this.evidencePath, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as PersistedEvidenceObservation);
      this.state.evidenceObservations = normalizeEvidenceObservations([
        ...this.state.evidenceObservations,
        ...persisted,
      ]);
    }
    this.persist();
  }

  snapshot(): EngagementState {
    return structuredClone(this.state);
  }

  restore(checkpoint: EngagementCheckpoint): void {
    if (
      checkpoint.targets &&
      JSON.stringify(checkpoint.targets) !== JSON.stringify(this.state.targets)
    ) {
      throw new Error(
        "Engagement checkpoint does not match the authorized target contract",
      );
    }
    if (
      JSON.stringify(checkpoint.objectives) !==
      JSON.stringify(this.state.objectives)
    ) {
      throw new Error(
        "Engagement checkpoint does not match the authorized objective contract",
      );
    }
    const expectedServices = new Map(
      this.state.coverage.map((cell) => [
        engagementCoverageCellId(cell.targetId, cell.objectiveId),
        cell.serviceId,
      ]),
    );
    const expected = new Set(
      this.state.coverage.map((cell) =>
        engagementCoverageCellId(cell.targetId, cell.objectiveId),
      ),
    );
    const actual = new Set(
      checkpoint.coverage.map((cell) =>
        engagementCoverageCellId(cell.targetId, cell.objectiveId),
      ),
    );
    if (
      expected.size !== actual.size ||
      checkpoint.coverage.length !== expected.size ||
      [...actual].some((id) => !expected.has(id))
    ) {
      throw new Error("Engagement checkpoint changed the coverage contract");
    }
    for (const cell of checkpoint.coverage) {
      if (
        expectedServices.get(
          engagementCoverageCellId(cell.targetId, cell.objectiveId),
        ) !== cell.serviceId
      ) {
        throw new Error("Engagement checkpoint changed coverage ownership");
      }
    }
    this.state = applyCheckpoint(this.state, checkpoint);
    this.persist();
  }

  saveMissions(missions: EngagementMissionState): void {
    this.state.missions = structuredClone(missions);
    this.persist();
  }

  saveConcurrency(concurrency: number): void {
    if (!Number.isInteger(concurrency) || concurrency < 1)
      throw new Error("Invalid engagement concurrency");
    this.state.concurrency = concurrency;
    this.persist();
  }

  recordInspectedTargets(targetIds: string[]): void {
    const missions = this.state.missions;
    if (!missions || missions.planningStatus === "complete") return;
    for (const id of targetIds) this.getTarget(id);
    missions.inspectedTargetIds = unique([
      ...(missions.inspectedTargetIds ?? []),
      ...targetIds,
    ]);
    this.persist();
  }

  defineMission(mission: EngagementMission): void {
    const state = this.state.missions;
    if (!state || state.planningStatus === "complete")
      throw new Error("Mission definitions require an unsealed grouped plan");
    if (
      !mission.purpose.trim() ||
      !mission.rationale.trim() ||
      !mission.coverage.length
    )
      throw new Error("Missions require purpose, rationale, and coverage");
    for (const cell of mission.coverage) {
      if (
        !this.getTarget(cell.targetId).objectiveIds.includes(cell.objectiveId)
      )
        throw new Error(
          `Objective ${cell.objectiveId} is not assigned to target ${cell.targetId}`,
        );
    }
    if (mission.requirements?.length) {
      const requirementIds = mission.requirements.map((item) => item.id);
      if (new Set(requirementIds).size !== requirementIds.length) {
        throw new Error("Mission requirement IDs must be unique");
      }
      const requirementCoverage = mission.requirements.flatMap(
        (requirement) => requirement.coverage,
      );
      const requirementCells = requirementCoverage.map((cell) =>
        engagementCoverageCellId(cell.targetId, cell.objectiveId),
      );
      const missionCells = mission.coverage.map((cell) =>
        engagementCoverageCellId(cell.targetId, cell.objectiveId),
      );
      if (
        new Set(requirementCells).size !== requirementCells.length ||
        requirementCells.length !== missionCells.length ||
        requirementCells.some((cell) => !missionCells.includes(cell))
      ) {
        throw new Error(
          "Canonical requirements must partition the mission source coverage exactly once",
        );
      }
    }
    for (const id of [
      ...mission.supportingTargetIds,
      ...mission.contextTargetIds,
    ])
      this.getTarget(id);
    const index = state.missions.findIndex((item) => item.id === mission.id);
    if (index >= 0 && state.missions[index]?.status !== "planned")
      throw new Error("An executed mission cannot be edited");
    if (index >= 0) state.missions[index] = structuredClone(mission);
    else state.missions.push(structuredClone(mission));
    state.planningStatus = "partial";
    this.persist();
  }

  deletePlannedMission(id: string): void {
    const state = this.state.missions;
    const mission = state?.missions.find((item) => item.id === id);
    if (
      !state ||
      state.planningStatus === "complete" ||
      mission?.status !== "planned"
    )
      throw new Error("Only unsealed planned missions can be deleted");
    state.missions = state.missions.filter((item) => item.id !== id);
    this.persist();
  }

  saveModels(input: {
    lead: EngagementModelConfig;
    worker: EngagementModelConfig;
    judge?: EngagementModelConfig;
  }): void {
    this.state.models = structuredClone(input);
    this.persist();
  }

  configureActors(actors: EngagementActorRecord[]): EngagementActorState {
    const ids = actors.map((actor) => actor.id);
    if (new Set(ids).size !== ids.length)
      throw new Error("Engagement actor IDs must be unique");
    for (const actor of actors) {
      if (!actor.label.trim() || !actor.role.trim())
        throw new Error("Engagement actors require a label and role");
      if (
        actor.status === "ready" &&
        actor.role !== "anonymous" &&
        actor.credentialIds.length === 0
      )
        throw new Error("Ready authenticated actors require credentials");
      if (actor.status === "unavailable" && !actor.unavailableReason?.trim())
        throw new Error("Unavailable actors require a reason");
      for (const targetId of actor.targetIds) this.getTarget(targetId);
      for (const serviceId of actor.serviceIds) this.getService(serviceId);
    }
    this.state.actors = {
      status: "complete",
      actors: actors.map((actor) => ({
        ...structuredClone(actor),
        credentialIds: unique(actor.credentialIds),
        targetIds: unique(actor.targetIds),
        serviceIds: unique(actor.serviceIds),
      })),
    };
    this.persist();
    return structuredClone(this.state.actors);
  }

  applyDeploymentPreflight(
    artifact: DeploymentPreflightArtifact,
    dispositions: DeploymentPrerequisiteDisposition[],
  ): void {
    if (artifact.status !== "sealed")
      throw new Error("Deployment preflight must be sealed before applying it");
    if (this.state.deploymentPreflight) {
      if (
        JSON.stringify(this.state.deploymentPreflight) !==
        JSON.stringify(artifact)
      )
        throw new Error("Deployment preflight changed after it was applied");
      return;
    }
    for (const disposition of dispositions) {
      if (disposition.status !== "blocked") continue;
      if (disposition.evidence.length === 0)
        throw new Error("Blocked preflight work requires evidence");
      for (const association of disposition.coverage) {
        const cell = this.state.coverage.find(
          (candidate) =>
            candidate.targetId === association.targetId &&
            candidate.objectiveId === association.objectiveId,
        );
        if (!cell)
          throw new Error(
            `Unknown preflight coverage ${association.targetId}:${association.objectiveId}`,
          );
        if (TERMINAL_COVERAGE.has(cell.status) && cell.status !== "blocked")
          throw new Error(
            "Deployment preflight cannot rewrite tested coverage",
          );
        if (cell.status === "running")
          throw new Error("Deployment preflight cannot block running coverage");
        cell.status = "blocked";
        cell.summary = `Deployment prerequisite unavailable: ${disposition.unavailableCapabilityIds.join(", ")}`;
        cell.evidence = unique([...cell.evidence, ...disposition.evidence]);
      }
    }
    this.state.deploymentPreflight = structuredClone(artifact);
    this.refreshServiceBaselines();
    this.persist();
  }

  recordFindingConsolidation(
    consolidation: EngagementFindingConsolidationState,
  ): void {
    if (
      this.state.findingConsolidation &&
      JSON.stringify(this.state.findingConsolidation) ===
        JSON.stringify(consolidation)
    )
      return;
    this.state.findingConsolidation = structuredClone(consolidation);
    this.persist();
  }

  addMission(mission: EngagementMission): void {
    const missions = this.state.missions ?? {
      planningStatus: "pending" as const,
      missions: [],
    };
    if (missions.missions.some((candidate) => candidate.id === mission.id)) {
      throw new Error(`Duplicate engagement mission: ${mission.id}`);
    }
    missions.missions.push(structuredClone(mission));
    missions.planningStatus = "partial";
    this.state.missions = missions;
    this.persist();
  }

  setMissionPlanningComplete(): EngagementMissionState {
    const missions = this.state.missions ?? {
      planningStatus: "pending" as const,
      missions: [],
    };
    const assignments = missions.missions.flatMap((mission) =>
      mission.coverage.map((cell) =>
        engagementCoverageCellId(cell.targetId, cell.objectiveId),
      ),
    );
    const assigned = new Set(assignments);
    if (assigned.size !== assignments.length) {
      throw new Error(
        "Mission plan assigns a coverage obligation more than once",
      );
    }
    const missing = this.state.coverage.filter(
      (cell) =>
        !assigned.has(
          engagementCoverageCellId(cell.targetId, cell.objectiveId),
        ),
    );
    if (missing.length > 0) {
      throw new Error(
        `Mission plan omits ${missing.length} required coverage obligation(s)`,
      );
    }
    const expected = new Set(
      this.state.coverage.map((cell) =>
        engagementCoverageCellId(cell.targetId, cell.objectiveId),
      ),
    );
    if (assignments.some((id) => !expected.has(id)))
      throw new Error("Mission plan contains unknown coverage obligations");
    const visited = new Set<string>();
    const visiting = new Set<string>();
    const visit = (id: string): void => {
      if (visiting.has(id))
        throw new Error("Mission prerequisites contain a cycle");
      if (visited.has(id)) return;
      const mission = missions.missions.find((item) => item.id === id);
      if (!mission) throw new Error(`Unknown prerequisite mission: ${id}`);
      visiting.add(id);
      for (const prerequisite of mission.prerequisiteMissionIds)
        visit(prerequisite);
      visiting.delete(id);
      visited.add(id);
    };
    for (const mission of missions.missions) visit(mission.id);
    const singletonTargets = new Set<string>();
    let primaryTargetCount = 0;
    for (const mission of missions.missions) {
      const targets = unique(mission.coverage.map((cell) => cell.targetId));
      primaryTargetCount += targets.length;
      if (targets.length === 1) {
        if (!mission.singletonJustification?.trim())
          throw new Error(
            `Singleton mission ${mission.id} requires justification`,
          );
        singletonTargets.add(targets[0] as string);
      }
    }
    const average = missions.missions.length
      ? primaryTargetCount / missions.missions.length
      : 0;
    if (
      this.state.targets.length >= 8 &&
      (singletonTargets.size / this.state.targets.length > 0.25 || average < 2)
    )
      throw new Error(
        "Regroup the plan: at most 25% singleton targets and at least two primary targets per mission on average are required",
      );
    const inspected = new Set(missions.inspectedTargetIds ?? []);
    if (this.state.targets.some((target) => !inspected.has(target.id)))
      throw new Error(
        "Read the complete target manifest before sealing the mission plan",
      );
    for (const mission of missions.missions) {
      for (const requirement of mission.requirements ?? []) {
        if (requirement.coverage.length < 2) continue;
        const missingContext = unique(
          requirement.coverage.map((cell) => cell.targetId),
        ).filter((targetId) => !this.state.contextReads?.[targetId]?.complete);
        if (missingContext.length > 0) {
          throw new Error(
            `Read complete target context before consolidating requirement ${requirement.id}: ${missingContext.join(", ")}`,
          );
        }
      }
    }
    missions.metrics = {
      primaryTargetsPerMission: average,
      singletonTargets: singletonTargets.size,
    };
    for (const mission of missions.missions) {
      if (mission.status === "planned") mission.status = "queued";
      for (const assignment of mission.coverage) {
        const cell = this.state.coverage.find(
          (candidate) =>
            candidate.targetId === assignment.targetId &&
            candidate.objectiveId === assignment.objectiveId,
        );
        if (!cell) throw new Error("Missing mission coverage");
        cell.missionId = mission.id;
        if (cell.status === "pending") cell.status = "assigned";
      }
    }
    missions.planningStatus = "complete";
    this.state.missions = missions;
    this.persist();
    return structuredClone(missions);
  }

  setMissionStatus(
    missionId: string,
    status: EngagementMission["status"],
  ): EngagementMission {
    const mission = this.state.missions?.missions.find(
      (candidate) => candidate.id === missionId,
    );
    if (!mission) throw new Error(`Unknown engagement mission: ${missionId}`);
    mission.status = status;
    if (status === "running") mission.startedAt = new Date().toISOString();
    if (status === "completed" || status === "failed") {
      mission.completedAt = new Date().toISOString();
    }
    this.persist();
    return structuredClone(mission);
  }

  settleMissionRequirement(input: {
    workerId: string;
    coverage: EngagementMissionCoverage[];
    status: Extract<CoverageStatus, "impact-proven" | "exhausted" | "blocked">;
    summary: string;
    evidence: string[];
  }): ObjectiveCoverage[] {
    return this.settleMissionRequirements([input]);
  }

  settleMissionRequirements(
    inputs: Array<{
      workerId: string;
      coverage: EngagementMissionCoverage[];
      status: Extract<
        CoverageStatus,
        "impact-proven" | "exhausted" | "blocked"
      >;
      summary: string;
      evidence: string[];
    }>,
  ): ObjectiveCoverage[] {
    const updates = inputs.flatMap((input) =>
      input.coverage.map(({ targetId, objectiveId }) => ({
        input,
        targetId,
        objectiveId,
      })),
    );
    const ids = updates.map(({ targetId, objectiveId }) =>
      engagementCoverageCellId(targetId, objectiveId),
    );
    if (new Set(ids).size !== ids.length) {
      throw new Error("Mission requirement batch contains duplicate coverage");
    }
    const cells = updates.map(({ input, targetId, objectiveId }) => {
      if (input.status === "impact-proven" && input.evidence.length === 0) {
        throw new Error("Impact-proven mission coverage requires evidence");
      }
      const cell = this.state.coverage.find(
        (candidate) =>
          candidate.targetId === targetId &&
          candidate.objectiveId === objectiveId,
      );
      if (
        !cell ||
        cell.workerId !== input.workerId ||
        cell.status !== "running"
      ) {
        throw new Error(
          `Worker no longer owns running coverage ${targetId}:${objectiveId}`,
        );
      }
      return { cell, input };
    });
    for (const { cell, input } of cells) {
      cell.status = input.status;
      cell.summary = input.summary;
      cell.evidence = unique([...cell.evidence, ...input.evidence]);
    }
    this.refreshServiceBaselines();
    this.persist();
    return structuredClone(cells.map(({ cell }) => cell));
  }

  checkpoint(): EngagementCheckpoint {
    return structuredClone({
      version: 4,
      contextReads: this.state.contextReads,
      concurrency: this.state.concurrency,
      missions: this.state.missions,
      models: this.state.models,
      targets: this.state.targets,
      objectives: this.state.objectives,
      services: this.state.services.map(({ id, baselineStatus, summary }) => ({
        id,
        baselineStatus,
        summary,
      })),
      coverage: this.state.coverage,
      capabilities: this.state.capabilities,
      impactProofs: this.state.impactProofs,
      evidenceObservations: this.state.evidenceObservations,
      chains: this.state.chains,
      workers: this.state.workers,
      actors: this.state.actors,
      deploymentPreflight: this.state.deploymentPreflight,
      findingConsolidation: this.state.findingConsolidation,
      chainExplore: this.state.chainExplore,
      updatedAt: this.state.updatedAt,
    });
  }

  recordEvidenceObservation(observation: PersistedEvidenceObservation): void {
    const key = evidenceObservationKey(observation);
    if (
      this.state.evidenceObservations.some(
        (candidate) => evidenceObservationKey(candidate) === key,
      )
    ) {
      return;
    }
    const persisted = structuredClone(observation);
    this.state.evidenceObservations.push(persisted);
    this.state.updatedAt = new Date().toISOString();
    mkdirSync(dirname(this.evidencePath), { recursive: true });
    appendFileSync(this.evidencePath, `${JSON.stringify(persisted)}\n`, "utf8");
  }

  recordContextRead(
    targetId: string,
    receipt: NonNullable<EngagementState["contextReads"]>[string],
  ): void {
    this.getTarget(targetId);
    const previous = this.state.contextReads?.[targetId];
    if (
      previous?.version &&
      receipt.version &&
      previous.version !== receipt.version
    )
      throw new Error(
        "Target context changed since the engagement checkpoint; review the snapshot before resuming",
      );
    const next = {
      ...receipt,
      complete: Boolean(previous?.complete || receipt.complete),
    };
    if (JSON.stringify(previous) === JSON.stringify(next)) return;
    this.state.contextReads = {
      ...this.state.contextReads,
      [targetId]: next,
    };
    this.persist();
  }

  getService(id: string): EngagementService {
    const service = this.state.services.find(
      (candidate) => candidate.id === id,
    );
    if (!service) throw new Error(`Unknown engagement service: ${id}`);
    return structuredClone(service);
  }

  getObjective(id: string): EngagementObjective {
    const objective = this.state.objectives.find(
      (candidate) => candidate.id === id,
    );
    if (!objective) throw new Error(`Unknown engagement objective: ${id}`);
    return structuredClone(objective);
  }

  getTarget(id: string): EngagementTargetRecord {
    const target = this.state.targets.find((candidate) => candidate.id === id);
    if (!target) throw new Error(`Unknown engagement target: ${id}`);
    return structuredClone(target);
  }

  getCapability(id: string): EngagementCapability {
    const capability = this.state.capabilities.find(
      (candidate) => candidate.id === id,
    );
    if (!capability) throw new Error(`Unknown engagement capability: ${id}`);
    return structuredClone(capability);
  }

  markServiceBaseline(
    serviceId: string,
    status: ServiceCoverageStatus,
    summary?: string,
  ): EngagementService {
    const service = this.state.services.find(
      (candidate) => candidate.id === serviceId,
    );
    if (!service) throw new Error(`Unknown engagement service: ${serviceId}`);
    service.baselineStatus = status;
    service.summary = summary?.trim() || undefined;
    this.persist();
    return structuredClone(service);
  }

  markObjectiveCoverage(input: {
    targetId: string;
    objectiveId: string;
    serviceId: string;
    status: CoverageStatus;
    workerId?: string | null;
    summary?: string;
    evidence?: string[];
  }): ObjectiveCoverage {
    if (
      input.status === "impact-proven" &&
      unique(input.evidence ?? []).length === 0
    ) {
      throw new Error("Impact-proven objective coverage requires evidence");
    }
    const target = this.getTarget(input.targetId);
    if (
      target.serviceId !== input.serviceId ||
      !target.objectiveIds.includes(input.objectiveId)
    ) {
      throw new Error(
        `Objective ${input.objectiveId} is not assigned to target ${input.targetId}`,
      );
    }
    const objective = this.getObjective(input.objectiveId);
    if (!objective.relevantServiceIds.includes(input.serviceId)) {
      throw new Error(
        `Service ${input.serviceId} is not relevant to objective ${input.objectiveId}`,
      );
    }
    const coverage = this.state.coverage.find(
      (candidate) =>
        candidate.targetId === input.targetId &&
        candidate.objectiveId === input.objectiveId &&
        candidate.serviceId === input.serviceId,
    );
    if (!coverage) throw new Error("Missing objective coverage entry");
    coverage.status = input.status;
    if (input.workerId !== undefined) {
      if (input.workerId === null) delete coverage.workerId;
      else coverage.workerId = input.workerId;
    }
    coverage.summary = input.summary?.trim() || coverage.summary;
    coverage.evidence = unique([
      ...coverage.evidence,
      ...(input.evidence ?? []),
    ]);
    this.refreshServiceBaselines();
    this.persist();
    return structuredClone(coverage);
  }

  claimCoverageCells(input: {
    workerId: string;
    cells: Array<{ targetId: string; objectiveId: string }>;
    includeNeedsLead?: boolean;
  }): ObjectiveCoverage[] {
    const claimed: ObjectiveCoverage[] = [];
    for (const cell of input.cells) {
      const coverage = this.state.coverage.find(
        (candidate) =>
          candidate.targetId === cell.targetId &&
          candidate.objectiveId === cell.objectiveId &&
          (candidate.status === "pending" ||
            candidate.status === "assigned" ||
            (input.includeNeedsLead && candidate.status === "needs-lead")),
      );
      if (!coverage) continue;
      coverage.status = "running";
      coverage.workerId = input.workerId;
      claimed.push(structuredClone(coverage));
    }
    if (claimed.length > 0) {
      this.refreshServiceBaselines();
      this.persist();
    }
    return claimed;
  }

  settleCoverageCell(input: {
    targetId: string;
    objectiveId: string;
    workerId: string;
    status: Exclude<CoverageStatus, "running">;
    summary: string;
    evidence?: string[];
    attempted?: boolean;
  }): ObjectiveCoverage | null {
    const coverage = this.state.coverage.find(
      (candidate) =>
        candidate.targetId === input.targetId &&
        candidate.objectiveId === input.objectiveId,
    );
    if (!coverage || coverage.workerId !== input.workerId) return null;
    return this.settleCoverageCells([input])[0] ?? null;
  }

  settleCoverageCells(
    inputs: Array<{
      targetId: string;
      objectiveId: string;
      workerId: string;
      status: Exclude<CoverageStatus, "running">;
      summary: string;
      evidence?: string[];
      attempted?: boolean;
    }>,
  ): ObjectiveCoverage[] {
    const ids = inputs.map(({ targetId, objectiveId }) =>
      engagementCoverageCellId(targetId, objectiveId),
    );
    if (new Set(ids).size !== ids.length) {
      throw new Error("Coverage settlement batch contains duplicate cells");
    }
    const cells = inputs.map((input) => {
      if (
        input.status === "impact-proven" &&
        unique(input.evidence ?? []).length === 0
      ) {
        throw new Error("Impact-proven objective coverage requires evidence");
      }
      const cell = this.state.coverage.find(
        (candidate) =>
          candidate.targetId === input.targetId &&
          candidate.objectiveId === input.objectiveId,
      );
      if (!cell || cell.workerId !== input.workerId) {
        throw new Error(
          `Worker no longer owns coverage ${input.targetId}:${input.objectiveId}`,
        );
      }
      return { cell, input };
    });
    for (const { cell, input } of cells) {
      cell.status = input.status;
      cell.summary = input.summary.trim();
      cell.evidence = unique([...cell.evidence, ...(input.evidence ?? [])]);
      if (input.attempted !== false) cell.attempts += 1;
      delete cell.workerId;
    }
    this.refreshServiceBaselines();
    this.persist();
    return structuredClone(cells.map(({ cell }) => cell));
  }

  upsertCapability(
    input: Omit<EngagementCapability, "id" | "updatedAt"> & { id?: string },
  ): EngagementCapability {
    for (const serviceId of input.serviceIds) this.getService(serviceId);
    for (const targetId of input.targetIds) this.getTarget(targetId);
    for (const objectiveId of input.objectiveIds)
      this.getObjective(objectiveId);
    const id =
      input.id ?? `cap_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
    const capability: EngagementCapability = {
      ...input,
      id,
      serviceIds: unique(input.serviceIds),
      targetIds: unique(input.targetIds),
      objectiveIds: unique(input.objectiveIds),
      evidence: unique(input.evidence),
      nextSteps: unique(input.nextSteps),
      updatedAt: new Date().toISOString(),
    };
    const index = this.state.capabilities.findIndex(
      (candidate) => candidate.id === id,
    );
    if (index >= 0) this.state.capabilities[index] = capability;
    else this.state.capabilities.push(capability);
    this.persist();
    return structuredClone(capability);
  }

  addImpactProof(input: Omit<ImpactProof, "id" | "createdAt">): ImpactProof {
    if (
      unique([
        ...input.findingIds,
        ...input.capabilityIds,
        ...input.artifactPaths,
        ...input.observationRefs,
      ]).length === 0
    ) {
      throw new Error("Impact proofs require at least one evidence reference");
    }
    for (const serviceId of input.serviceIds) this.getService(serviceId);
    for (const targetId of input.targetIds) this.getTarget(targetId);
    for (const objectiveId of input.objectiveIds)
      this.getObjective(objectiveId);
    for (const capabilityId of input.capabilityIds)
      this.getCapability(capabilityId);
    const proof: ImpactProof = {
      ...input,
      id: `proof_${randomUUID().replaceAll("-", "").slice(0, 12)}`,
      objectiveIds: unique(input.objectiveIds),
      serviceIds: unique(input.serviceIds),
      targetIds: unique(input.targetIds),
      findingIds: unique(input.findingIds),
      capabilityIds: unique(input.capabilityIds),
      artifactPaths: unique(input.artifactPaths),
      observationRefs: unique(input.observationRefs),
      createdAt: new Date().toISOString(),
    };
    this.state.impactProofs.push(proof);
    this.persist();
    return structuredClone(proof);
  }

  upsertChain(
    input: Omit<
      EngagementChain,
      "id" | "createdAt" | "updatedAt" | "evidenceQuality" | "steps"
    > & {
      id?: string;
      steps: Array<
        Pick<EngagementChainStep, "title" | "description"> &
          Partial<Omit<EngagementChainStep, "id" | "title" | "description">> & {
            id?: string;
          }
      >;
    },
  ): EngagementChain {
    const steps = input.steps.map((step) => ({
      ...step,
      findingIds: step.findingIds ?? [],
      capabilityIds: step.capabilityIds ?? [],
      impactProofIds: step.impactProofIds ?? [],
      objectiveIds: step.objectiveIds ?? [],
      serviceIds: step.serviceIds ?? [],
      targetIds: step.targetIds ?? [],
      artifactPaths: step.artifactPaths ?? [],
      observationRefs: step.observationRefs ?? [],
      evidence: step.evidence ?? [],
    }));
    if (input.status === "impact-proven" && !input.severity) {
      throw new Error("Impact-proven chains require a severity");
    }
    if (
      input.status === "impact-proven" &&
      unique([
        ...input.findingIds,
        ...input.capabilityIds,
        ...input.impactProofIds,
        ...input.evidence,
      ]).length === 0
    ) {
      throw new Error("Impact-proven chains require linked evidence");
    }
    if (input.status === "blocked" && !input.blocker?.trim()) {
      throw new Error("Blocked chains require a blocker");
    }
    const minimumSteps = input.status === "impact-proven" ? 2 : 1;
    if (steps.length < minimumSteps) {
      throw new Error(
        `${input.status} chains require at least ${minimumSteps} structured step(s)`,
      );
    }
    for (const serviceId of input.serviceIds) this.getService(serviceId);
    for (const targetId of input.targetIds) this.getTarget(targetId);
    for (const objectiveId of input.objectiveIds)
      this.getObjective(objectiveId);
    for (const capabilityId of input.capabilityIds)
      this.getCapability(capabilityId);
    const proofIds = new Set(this.state.impactProofs.map((proof) => proof.id));
    if (input.impactProofIds.some((id) => !proofIds.has(id))) {
      throw new Error("Chain references an unknown impact proof");
    }
    for (const step of steps) {
      if (
        unique([
          ...step.findingIds,
          ...step.capabilityIds,
          ...step.impactProofIds,
          ...step.artifactPaths,
          ...step.observationRefs,
          ...step.evidence,
        ]).length === 0
      ) {
        throw new Error(
          "Every chain step requires a linked evidence reference",
        );
      }
      for (const capabilityId of step.capabilityIds)
        this.getCapability(capabilityId);
      for (const serviceId of step.serviceIds) this.getService(serviceId);
      for (const targetId of step.targetIds) this.getTarget(targetId);
      for (const objectiveId of step.objectiveIds)
        this.getObjective(objectiveId);
      if (step.impactProofIds.some((id) => !proofIds.has(id))) {
        throw new Error("Chain step references an unknown impact proof");
      }
    }

    const now = new Date().toISOString();
    const id =
      input.id ?? `chain_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
    const previous = this.state.chains.find((chain) => chain.id === id);
    const chain: EngagementChain = {
      ...input,
      id,
      title: input.title.trim(),
      description: input.description.trim(),
      impact: input.impact.trim(),
      remediation: input.remediation?.trim() || undefined,
      findingIds: unique([
        ...input.findingIds,
        ...steps.flatMap((step) => step.findingIds),
      ]),
      capabilityIds: unique([
        ...input.capabilityIds,
        ...steps.flatMap((step) => step.capabilityIds),
      ]),
      impactProofIds: unique([
        ...input.impactProofIds,
        ...steps.flatMap((step) => step.impactProofIds),
      ]),
      objectiveIds: unique([
        ...input.objectiveIds,
        ...steps.flatMap((step) => step.objectiveIds),
      ]),
      serviceIds: unique([
        ...input.serviceIds,
        ...steps.flatMap((step) => step.serviceIds),
      ]),
      targetIds: unique([
        ...input.targetIds,
        ...steps.flatMap((step) => step.targetIds),
      ]),
      evidence: unique(input.evidence),
      steps: steps.map((step, index) => ({
        ...step,
        id:
          step.id ??
          stableId("step", `${id}:${index}:${step.title}:${step.description}`),
        title: step.title.trim(),
        description: step.description.trim(),
        findingIds: unique(step.findingIds),
        capabilityIds: unique(step.capabilityIds),
        impactProofIds: unique(step.impactProofIds),
        objectiveIds: unique(step.objectiveIds),
        serviceIds: unique(step.serviceIds),
        targetIds: unique(step.targetIds),
        artifactPaths: unique(step.artifactPaths),
        observationRefs: unique(step.observationRefs),
        evidence: unique(step.evidence),
      })),
      evidenceQuality: "verified",
      blocker: input.blocker?.trim() || undefined,
      createdAt: previous?.createdAt ?? now,
      updatedAt: now,
    };
    const index = this.state.chains.findIndex(
      (candidate) => candidate.id === id,
    );
    if (index >= 0) this.state.chains[index] = chain;
    else this.state.chains.push(chain);
    this.persist();
    return structuredClone(chain);
  }

  setChainExplore(
    status: ChainExploreStatus,
    summary?: string,
    evidence: string[] = [],
  ): EngagementState["chainExplore"] {
    if (
      status === "impact-proven" &&
      unique([...this.state.chainExplore.evidence, ...evidence]).length === 0
    ) {
      throw new Error("Impact-proven chain exploration requires evidence");
    }
    if (TERMINAL_CHAIN.has(status)) {
      const completion = this.completion();
      if (
        completion.missingCoverageCellIds.length > 0 ||
        completion.missingServiceIds.length > 0 ||
        completion.unresolvedCapabilityIds.length > 0 ||
        completion.missionPlanningPending ||
        completion.activeMissionIds.length > 0 ||
        completion.activeWorkerIds.length > 0
      ) {
        throw new Error(
          "Chain exploration cannot be closed until coverage, service baselines, capabilities, missions and workers are terminal",
        );
      }
    }
    this.state.chainExplore = {
      status,
      summary: summary?.trim() || undefined,
      evidence: unique([...this.state.chainExplore.evidence, ...evidence]),
    };
    this.persist();
    return structuredClone(this.state.chainExplore);
  }

  registerWorker(
    input: Omit<EngagementWorkerRecord, "status" | "startedAt">,
  ): EngagementWorkerRecord {
    const worker: EngagementWorkerRecord = {
      ...input,
      serviceIds: unique(input.serviceIds),
      targetIds: unique(input.targetIds),
      objectiveIds: unique(input.objectiveIds),
      capabilityIds: unique(input.capabilityIds),
      actorIds: input.actorIds ? unique(input.actorIds) : undefined,
      status: "queued",
    };
    this.state.workers.push(worker);
    this.persist();
    return structuredClone(worker);
  }

  startWorker(workerId: string): EngagementWorkerRecord {
    const worker = this.state.workers.find(
      (candidate) => candidate.id === workerId,
    );
    if (!worker) throw new Error(`Unknown engagement worker: ${workerId}`);
    if (worker.status !== "queued") {
      throw new Error(`Worker ${workerId} is not queued`);
    }
    worker.status = "running";
    worker.startedAt = new Date().toISOString();
    this.persist();
    return structuredClone(worker);
  }

  completeWorker(
    workerId: string,
    status: "completed" | "failed",
    summary: string,
  ): EngagementWorkerRecord {
    const worker = this.state.workers.find(
      (candidate) => candidate.id === workerId,
    );
    if (!worker) throw new Error(`Unknown engagement worker: ${workerId}`);
    worker.status = status;
    worker.summary = summary.trim();
    worker.completedAt = new Date().toISOString();
    this.persist();
    return structuredClone(worker);
  }

  restartWorker(workerId: string): EngagementWorkerRecord {
    const worker = this.state.workers.find(
      (candidate) => candidate.id === workerId,
    );
    if (!worker) throw new Error(`Unknown engagement worker: ${workerId}`);
    worker.status = "running";
    worker.summary = undefined;
    worker.startedAt = new Date().toISOString();
    worker.completedAt = undefined;
    this.persist();
    return structuredClone(worker);
  }

  /**
   * Convert workers left running by a terminated host into resumable failed
   * records and reopen the coverage they owned. This is called once when a
   * lead process starts, before it can spawn any new in-process workers.
   */
  reconcileInterruptedWorkers(): string[] {
    const interrupted = this.state.workers.filter(
      (worker) => worker.status === "running",
    );
    if (interrupted.length === 0) return [];

    const interruptedIds = new Set(interrupted.map((worker) => worker.id));
    const interruptedAt = new Date().toISOString();
    for (const worker of interrupted) {
      worker.status = "failed";
      worker.summary =
        "Interrupted before completion; any preserved conversation is available for follow-up.";
      worker.completedAt = interruptedAt;
      const mission = this.state.missions?.missions.find(
        (candidate) => candidate.workerId === worker.id,
      );
      if (mission) {
        mission.status = "failed";
        mission.completedAt = interruptedAt;
      }
    }
    for (const coverage of this.state.coverage) {
      if (
        coverage.status === "running" &&
        coverage.workerId &&
        interruptedIds.has(coverage.workerId)
      ) {
        coverage.status = "pending";
        delete coverage.workerId;
        coverage.summary = "Previous worker was interrupted before completion.";
      }
    }
    this.refreshServiceBaselines();
    for (const service of this.state.services) {
      const interruptedExplorer = interrupted.some(
        (worker) =>
          worker.mode === "explore" && worker.serviceIds.includes(service.id),
      );
      if (service.baselineStatus === "running" && interruptedExplorer) {
        service.baselineStatus = "pending";
        service.summary = "Previous exploration worker was interrupted.";
      }
    }
    this.persist();
    return [...interruptedIds];
  }

  completion(): EngagementCompletion {
    const incompleteCoverage = this.state.coverage.filter(
      (coverage) => !TERMINAL_COVERAGE.has(coverage.status),
    );
    const missingObjectiveIds = unique(
      incompleteCoverage.map((coverage) => coverage.objectiveId),
    );
    const missingCoverageCellIds = incompleteCoverage.map((coverage) =>
      engagementCoverageCellId(coverage.targetId, coverage.objectiveId),
    );
    const missingServiceIds = this.state.services
      .filter((service) => !TERMINAL_SERVICE.has(service.baselineStatus))
      .map((service) => service.id);
    const unresolvedCapabilityIds = this.state.capabilities
      .filter(
        (capability) =>
          capability.status === "candidate" ||
          (capability.status === "confirmed" &&
            capability.nextSteps.length > 0),
      )
      .map((capability) => capability.id);
    const chainExplorePending = !TERMINAL_CHAIN.has(
      this.state.chainExplore.status,
    );
    const missionPlanningPending =
      this.state.missions !== undefined &&
      this.state.missions.planningStatus !== "complete";
    const activeMissionIds =
      this.state.missions?.missions
        .filter(
          (mission) =>
            mission.status === "planned" ||
            mission.status === "queued" ||
            mission.status === "running",
        )
        .map((mission) => mission.id) ?? [];
    const activeWorkerIds = this.state.workers
      .filter(
        (worker) => worker.status === "queued" || worker.status === "running",
      )
      .map((worker) => worker.id);
    const tested = this.state.coverage.filter(
      (coverage) =>
        coverage.status === "impact-proven" || coverage.status === "exhausted",
    ).length;
    const blocked = this.state.coverage.filter(
      (coverage) => coverage.status === "blocked",
    ).length;
    return {
      complete:
        missingObjectiveIds.length === 0 &&
        missingCoverageCellIds.length === 0 &&
        missingServiceIds.length === 0 &&
        unresolvedCapabilityIds.length === 0 &&
        !missionPlanningPending &&
        activeMissionIds.length === 0 &&
        activeWorkerIds.length === 0 &&
        !chainExplorePending,
      missingObjectiveIds,
      missingCoverageCellIds,
      missingServiceIds,
      unresolvedCapabilityIds,
      chainExplorePending,
      missionPlanningPending,
      activeMissionIds,
      activeWorkerIds,
      coverageSummary: {
        tested,
        blocked,
        untested: this.state.coverage.length - tested - blocked,
        total: this.state.coverage.length,
      },
    };
  }

  private refreshServiceBaselines(): void {
    for (const service of this.state.services) {
      const targetIds = new Set(
        this.state.targets
          .filter((target) => target.serviceId === service.id)
          .map((target) => target.id),
      );
      const coverage = this.state.coverage.filter((cell) =>
        targetIds.has(cell.targetId),
      );
      if (coverage.length === 0) continue;
      if (coverage.every((cell) => TERMINAL_COVERAGE.has(cell.status))) {
        service.baselineStatus = coverage.every(
          (cell) => cell.status === "blocked",
        )
          ? "blocked"
          : "explored";
        service.summary = `Deterministic endpoint coverage completed for ${targetIds.size} target(s).`;
      } else if (coverage.some((cell) => cell.status === "running")) {
        service.baselineStatus = "running";
        service.summary = "Deterministic endpoint coverage is running.";
      } else {
        service.baselineStatus = "pending";
        service.summary = undefined;
      }
    }
  }

  private persist(): void {
    this.state.updatedAt = new Date().toISOString();
    atomicWrite(this.statePath, this.state);
  }
}

/** Durable directed messages for worker follow-up and final handoff. */
export class AgentMailbox {
  private readonly messagesPath: string;
  private readonly cursorsPath: string;

  constructor(sessionRootPath: string) {
    const directory = join(sessionRootPath, "coordination");
    this.messagesPath = join(directory, "agent-mailbox.jsonl");
    this.cursorsPath = join(directory, "agent-mailbox-cursors.json");
    mkdirSync(directory, { recursive: true });
  }

  send(
    input: Omit<AgentMailboxMessage, "id" | "sequence" | "timestamp">,
  ): AgentMailboxMessage {
    const messages = this.readMessages();
    const message: AgentMailboxMessage = {
      ...input,
      id: `msg_${randomUUID().replaceAll("-", "").slice(0, 12)}`,
      sequence: (messages.at(-1)?.sequence ?? 0) + 1,
      timestamp: new Date().toISOString(),
      taskName: input.taskName.trim().slice(0, 240),
      payload: input.payload.trim().slice(0, 32_000),
    };
    appendFileSync(this.messagesPath, `${JSON.stringify(message)}\n`, "utf8");
    return message;
  }

  take(recipientAgentId: string, limit = 20): AgentMailboxMessage[] {
    const cursors = existsSync(this.cursorsPath)
      ? (JSON.parse(readFileSync(this.cursorsPath, "utf8")) as Record<
          string,
          number
        >)
      : {};
    const cursor = cursors[recipientAgentId] ?? 0;
    const unread = this.readMessages()
      .filter(
        (message) =>
          message.recipientAgentId === recipientAgentId &&
          message.sequence > cursor,
      )
      .slice(0, Math.max(1, Math.min(limit, 100)));
    const last = unread.at(-1);
    if (last) {
      cursors[recipientAgentId] = last.sequence;
      atomicWrite(this.cursorsPath, cursors);
    }
    return unread;
  }

  private readMessages(): AgentMailboxMessage[] {
    if (!existsSync(this.messagesPath)) return [];
    return readFileSync(this.messagesPath, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as AgentMailboxMessage)
      .sort((left, right) => left.sequence - right.sequence);
  }
}
