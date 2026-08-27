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

export type CoverageStatus =
  | "pending"
  | "running"
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
export type EngagementWorkerMode = "targeted" | "fast-strike" | "explore";

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

export interface ObjectiveCoverage {
  objectiveId: string;
  serviceId: string;
  status: CoverageStatus;
  workerId?: string;
  summary?: string;
  evidence: string[];
}

export interface ImpactProof {
  id: string;
  description: string;
  objectiveIds: string[];
  serviceIds: string[];
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
  objectiveIds: string[];
  evidence: string[];
  nextSteps: string[];
  updatedAt: string;
}

export interface EngagementWorkerRecord {
  id: string;
  mission: string;
  mode: EngagementWorkerMode;
  serviceIds: string[];
  objectiveIds: string[];
  status: "running" | "completed" | "failed";
  summary?: string;
  startedAt: string;
  completedAt?: string;
}

export interface EngagementState {
  version: 1;
  rootTarget: string;
  operatorContext?: string;
  services: EngagementService[];
  objectives: EngagementObjective[];
  coverage: ObjectiveCoverage[];
  capabilities: EngagementCapability[];
  impactProofs: ImpactProof[];
  workers: EngagementWorkerRecord[];
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
  missingServiceIds: string[];
  unresolvedCapabilityIds: string[];
  chainExplorePending: boolean;
}

/** Compact durable state embedded in coordination tool results for host resume. */
export interface EngagementCheckpoint {
  version: 1;
  services: Array<Pick<EngagementService, "id" | "baselineStatus" | "summary">>;
  coverage: ObjectiveCoverage[];
  capabilities: EngagementCapability[];
  impactProofs: ImpactProof[];
  workers: EngagementWorkerRecord[];
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

    for (const text of target.objectives) {
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
    }
  }

  const services = [...serviceByOrigin.values()];
  const objectives = [...objectiveByText.values()];
  const coverage = objectives.flatMap((objective) =>
    objective.relevantServiceIds.map((serviceId) => ({
      objectiveId: objective.id,
      serviceId,
      status: "pending" as const,
      evidence: [],
    })),
  );
  return {
    version: 1,
    rootTarget,
    operatorContext,
    services,
    objectives,
    coverage,
    capabilities: [],
    impactProofs: [],
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

function isEngagementCheckpoint(value: unknown): value is EngagementCheckpoint {
  return (
    isRecord(value) &&
    value.version === 1 &&
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
    typeof record.rootTarget === "string" &&
    Array.isArray(record.objectives)
  );
}

function applyCheckpoint(
  seed: EngagementState,
  checkpoint: EngagementCheckpoint,
): EngagementState {
  const serviceUpdates = new Map(
    checkpoint.services.map((service) => [service.id, service]),
  );
  return {
    ...structuredClone(seed),
    services: seed.services.map((service) => ({
      ...service,
      ...serviceUpdates.get(service.id),
    })),
    coverage: structuredClone(checkpoint.coverage),
    capabilities: structuredClone(checkpoint.capabilities),
    impactProofs: structuredClone(checkpoint.impactProofs),
    workers: structuredClone(checkpoint.workers),
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
        return structuredClone(result.state);
      }
    }
  }
  return seed;
}

/** Single-writer, persisted engagement graph and coverage contract. */
export class EngagementStore {
  private readonly statePath: string;
  private state: EngagementState;

  static open(sessionRootPath: string, seed: EngagementState): EngagementStore {
    const statePath = join(sessionRootPath, "coordination", "engagement.json");
    if (!existsSync(statePath)) return new EngagementStore(statePath, seed);
    const parsed = JSON.parse(
      readFileSync(statePath, "utf8"),
    ) as EngagementState;
    if (parsed.version !== 1) {
      throw new Error(
        `Unsupported engagement state version: ${parsed.version}`,
      );
    }
    return new EngagementStore(statePath, parsed);
  }

  private constructor(statePath: string, state: EngagementState) {
    this.statePath = statePath;
    this.state = structuredClone(state);
    this.persist();
  }

  snapshot(): EngagementState {
    return structuredClone(this.state);
  }

  checkpoint(): EngagementCheckpoint {
    return structuredClone({
      version: 1,
      services: this.state.services.map(({ id, baselineStatus, summary }) => ({
        id,
        baselineStatus,
        summary,
      })),
      coverage: this.state.coverage,
      capabilities: this.state.capabilities,
      impactProofs: this.state.impactProofs,
      workers: this.state.workers,
      chainExplore: this.state.chainExplore,
      updatedAt: this.state.updatedAt,
    });
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
    objectiveId: string;
    serviceId: string;
    status: CoverageStatus;
    workerId?: string;
    summary?: string;
    evidence?: string[];
  }): ObjectiveCoverage {
    const objective = this.getObjective(input.objectiveId);
    if (!objective.relevantServiceIds.includes(input.serviceId)) {
      throw new Error(
        `Service ${input.serviceId} is not relevant to objective ${input.objectiveId}`,
      );
    }
    const coverage = this.state.coverage.find(
      (candidate) =>
        candidate.objectiveId === input.objectiveId &&
        candidate.serviceId === input.serviceId,
    );
    if (!coverage) throw new Error("Missing objective coverage entry");
    coverage.status = input.status;
    coverage.workerId = input.workerId ?? coverage.workerId;
    coverage.summary = input.summary?.trim() || coverage.summary;
    coverage.evidence = unique([
      ...coverage.evidence,
      ...(input.evidence ?? []),
    ]);
    this.persist();
    return structuredClone(coverage);
  }

  upsertCapability(
    input: Omit<EngagementCapability, "id" | "updatedAt"> & { id?: string },
  ): EngagementCapability {
    for (const serviceId of input.serviceIds) this.getService(serviceId);
    for (const objectiveId of input.objectiveIds)
      this.getObjective(objectiveId);
    const id =
      input.id ?? `cap_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
    const capability: EngagementCapability = {
      ...input,
      id,
      serviceIds: unique(input.serviceIds),
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
    const proof: ImpactProof = {
      ...input,
      id: `proof_${randomUUID().replaceAll("-", "").slice(0, 12)}`,
      objectiveIds: unique(input.objectiveIds),
      serviceIds: unique(input.serviceIds),
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

  setChainExplore(
    status: ChainExploreStatus,
    summary?: string,
    evidence: string[] = [],
  ): EngagementState["chainExplore"] {
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
      objectiveIds: unique(input.objectiveIds),
      status: "running",
      startedAt: new Date().toISOString(),
    };
    this.state.workers.push(worker);
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
    }
    for (const coverage of this.state.coverage) {
      if (
        coverage.status === "running" &&
        coverage.workerId &&
        interruptedIds.has(coverage.workerId)
      ) {
        coverage.status = "pending";
        coverage.summary = "Previous worker was interrupted before completion.";
      }
    }
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
    const missingObjectiveIds = this.state.objectives
      .filter(
        (objective) =>
          !this.state.coverage.some(
            (coverage) =>
              coverage.objectiveId === objective.id &&
              TERMINAL_COVERAGE.has(coverage.status),
          ),
      )
      .map((objective) => objective.id);
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
    return {
      complete:
        missingObjectiveIds.length === 0 &&
        missingServiceIds.length === 0 &&
        unresolvedCapabilityIds.length === 0 &&
        !chainExplorePending,
      missingObjectiveIds,
      missingServiceIds,
      unresolvedCapabilityIds,
      chainExplorePending,
    };
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
