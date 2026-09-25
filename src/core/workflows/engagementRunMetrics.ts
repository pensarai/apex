import { randomUUID } from "node:crypto";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { CodeCellResult } from "../agents/offSecAgent/codeMode/runtime";
import { writeExecutionMetrics } from "../session/execution-metrics";
import type { PentestWorkflowInput } from "./pentest";

export type EngagementRunRole = "planner" | "lead" | "worker" | "judge";

interface UsageBucket {
  calls: number;
  costReportedCalls: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  providerCost: number | null;
}

export interface EngagementRunMetricsArtifact {
  version: 1;
  startedAt: string;
  updatedAt: string;
  completedAt?: string;
  status: "running" | "completed" | "failed";
  wallRuntimeMs: number;
  roles: Record<string, Record<string, UsageBucket>>;
  totals: UsageBucket;
  code: {
    cells: number;
    completed: number;
    failed: number;
    terminated: number;
    nestedCalls: number;
    durationMs: number;
    maxConcurrency: number;
  };
  cost:
    | { status: "reported"; amount: number }
    | {
        status: "partial";
        amount: number;
        missing: Array<{ role: string; model: string }>;
      }
    | { status: "unavailable" };
}

type StepEvent = Parameters<
  NonNullable<PentestWorkflowInput["onStepFinish"]>
>[0];

const EMPTY_USAGE = (): UsageBucket => ({
  calls: 0,
  costReportedCalls: 0,
  inputTokens: 0,
  outputTokens: 0,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
  providerCost: null,
});

function number(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : 0;
}

function reportedCost(metadata: unknown): number | null {
  if (!metadata || typeof metadata !== "object") return null;
  const queue: unknown[] = [metadata];
  for (let depth = 0; depth < 4 && queue.length > 0; depth++) {
    const level = queue.splice(0);
    for (const value of level) {
      if (!value || typeof value !== "object") continue;
      for (const [key, child] of Object.entries(value)) {
        if (
          (key === "cost" || key === "totalCost" || key === "total_cost") &&
          typeof child === "number" &&
          Number.isFinite(child)
        )
          return child;
        if (child && typeof child === "object") queue.push(child);
      }
    }
  }
  return null;
}

function atomicWrite(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  renameSync(temporaryPath, path);
}

export class EngagementRunMetrics {
  private readonly startedAt = new Date();
  private readonly path: string;
  private completedAt?: string;
  private terminalStatus?: "completed" | "failed";
  private readonly roles: Record<string, Record<string, UsageBucket>> = {};
  private readonly code = {
    cells: 0,
    completed: 0,
    failed: 0,
    terminated: 0,
    nestedCalls: 0,
    durationMs: 0,
    maxConcurrency: 0,
  };

  constructor(private readonly sessionRootPath: string) {
    this.path = join(
      sessionRootPath,
      "coordination",
      "engagement-run-metrics.json",
    );
    this.persist(this.terminalStatus ?? "running");
  }

  record(role: EngagementRunRole, model: unknown, event: StepEvent): void {
    const modelId = String(model ?? "unknown");
    if (!this.roles[role]) this.roles[role] = {};
    const roleBuckets = this.roles[role];
    if (!roleBuckets[modelId]) roleBuckets[modelId] = EMPTY_USAGE();
    const bucket = roleBuckets[modelId];
    const usage = event.usage as typeof event.usage & {
      cacheReadTokens?: number;
      cacheWriteTokens?: number;
      inputTokenDetails?: {
        cacheReadTokens?: number;
        cacheWriteTokens?: number;
      };
    };
    bucket.calls += 1;
    bucket.inputTokens += number(usage.inputTokens);
    bucket.outputTokens += number(usage.outputTokens);
    bucket.cacheReadTokens += number(
      usage.cacheReadTokens ?? usage.inputTokenDetails?.cacheReadTokens,
    );
    bucket.cacheWriteTokens += number(
      usage.cacheWriteTokens ?? usage.inputTokenDetails?.cacheWriteTokens,
    );
    const cost = reportedCost(event.providerMetadata);
    if (cost !== null) {
      bucket.costReportedCalls += 1;
      bucket.providerCost = (bucket.providerCost ?? 0) + cost;
    }
    this.persist(this.terminalStatus ?? "running");
  }

  recordCode(
    _role: EngagementRunRole,
    _model: unknown,
    result: CodeCellResult,
  ) {
    if (result.status === "running") return;
    this.code.cells += 1;
    if (result.status === "completed") this.code.completed += 1;
    if (result.status === "failed") this.code.failed += 1;
    if (result.status === "terminated") this.code.terminated += 1;
    this.code.nestedCalls += result.metrics?.nestedCalls ?? 0;
    this.code.durationMs += result.metrics?.durationMs ?? 0;
    this.code.maxConcurrency = Math.max(
      this.code.maxConcurrency,
      result.metrics?.maxConcurrency ?? 0,
    );
    this.persist(this.terminalStatus ?? "running");
  }

  finish(status: "completed" | "failed"): void {
    this.terminalStatus ??= status;
    this.completedAt ??= new Date().toISOString();
    const artifact = this.persist(this.terminalStatus);
    writeExecutionMetrics({
      sessionRootPath: this.sessionRootPath,
      tokenUsage: {
        inputTokens: artifact.totals.inputTokens,
        outputTokens: artifact.totals.outputTokens,
        cacheReadTokens: artifact.totals.cacheReadTokens,
        cacheWriteTokens: artifact.totals.cacheWriteTokens,
        totalTokens: artifact.totals.inputTokens + artifact.totals.outputTokens,
      },
      runtime: "engagement-lead",
      elapsedSeconds: Math.floor(artifact.wallRuntimeMs / 1000),
    });
  }

  private persist(
    status: EngagementRunMetricsArtifact["status"],
  ): EngagementRunMetricsArtifact {
    const buckets = Object.values(this.roles).flatMap((models) =>
      Object.values(models),
    );
    const totals = buckets.reduce<UsageBucket>((total, bucket) => {
      total.calls += bucket.calls;
      total.costReportedCalls += bucket.costReportedCalls;
      total.inputTokens += bucket.inputTokens;
      total.outputTokens += bucket.outputTokens;
      total.cacheReadTokens += bucket.cacheReadTokens;
      total.cacheWriteTokens += bucket.cacheWriteTokens;
      if (bucket.providerCost !== null)
        total.providerCost = (total.providerCost ?? 0) + bucket.providerCost;
      return total;
    }, EMPTY_USAGE());
    const now = new Date();
    const modelCosts = Object.entries(this.roles).flatMap(([role, models]) =>
      Object.entries(models).map(([model, bucket]) => ({
        role,
        model,
        reported: bucket.calls > 0 && bucket.costReportedCalls === bucket.calls,
      })),
    );
    const missingCostModels = modelCosts
      .filter((entry) => !entry.reported)
      .map(({ role, model }) => ({ role, model }));
    const cost =
      totals.providerCost === null
        ? ({ status: "unavailable" } as const)
        : missingCostModels.length > 0
          ? ({
              status: "partial",
              amount: totals.providerCost,
              missing: missingCostModels,
            } as const)
          : ({ status: "reported", amount: totals.providerCost } as const);
    const artifact: EngagementRunMetricsArtifact = {
      version: 1,
      startedAt: this.startedAt.toISOString(),
      updatedAt: now.toISOString(),
      ...(status !== "running" && {
        completedAt: this.completedAt ?? now.toISOString(),
      }),
      status,
      wallRuntimeMs: now.getTime() - this.startedAt.getTime(),
      roles: this.roles,
      totals,
      code: { ...this.code },
      cost,
    };
    atomicWrite(this.path, artifact);
    return artifact;
  }
}
