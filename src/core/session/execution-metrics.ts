import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const EXECUTION_METRICS_FILENAME = "execution-metrics.json";

interface TokenUsageTotals {
  inputTokens: number;
  outputTokens: number;
  /** Cache-read tokens. Already included in inputTokens. */
  cacheReadTokens: number;
  /** Cache-write tokens (Anthropic prompt caching). */
  cacheWriteTokens: number;
  totalTokens: number;
}

interface ContextUsageMetrics {
  usedTokens: number;
  contextLimit: number;
  /** The model the sampled root call ran on. */
  modelId: string;
}

export interface ExecutionMetrics {
  tokenUsage: TokenUsageTotals;
  /** Latest root-call context sample; absent in legacy files. */
  contextUsage?: ContextUsageMetrics;
  runtime?: string;
  /** Accumulated wall-clock seconds the pentest has been actively running. */
  elapsedSeconds?: number;
  updatedAt: string;
}

interface WriteExecutionMetricsInput {
  sessionRootPath: string;
  /** Authoritative cumulative snapshot from the owning session. */
  tokenUsage?: Partial<TokenUsageTotals>;
  /** Replaces the context sample when provided; retained otherwise. */
  contextUsage?: ContextUsageMetrics;
  runtime?: string;
  elapsedSeconds?: number;
}

function toNonNegativeInteger(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function normalizeTokenUsage(
  value?: Partial<TokenUsageTotals>,
): TokenUsageTotals {
  const inputTokens = toNonNegativeInteger(value?.inputTokens);
  const outputTokens = toNonNegativeInteger(value?.outputTokens);
  const derivedTotal = inputTokens + outputTokens;
  const explicitTotal = toNonNegativeInteger(value?.totalTokens);

  return {
    inputTokens,
    outputTokens,
    // Legacy files lack cache fields — they hydrate as zero.
    cacheReadTokens: toNonNegativeInteger(value?.cacheReadTokens),
    cacheWriteTokens: toNonNegativeInteger(value?.cacheWriteTokens),
    // Cache reads are already inside inputTokens; total stays in + out.
    totalTokens: explicitTotal > 0 ? explicitTotal : derivedTotal,
  };
}

function normalizeContextUsage(
  value: unknown,
): ContextUsageMetrics | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const v = value as Partial<ContextUsageMetrics>;
  if (typeof v.modelId !== "string" || v.modelId.length === 0) return undefined;
  return {
    modelId: v.modelId,
    usedTokens: toNonNegativeInteger(v.usedTokens),
    contextLimit: toNonNegativeInteger(v.contextLimit),
  };
}

function metricsPath(sessionRootPath: string): string {
  return join(sessionRootPath, EXECUTION_METRICS_FILENAME);
}

function sessionJsonPath(sessionRootPath: string): string {
  return join(sessionRootPath, "session.json");
}

export function readExecutionMetrics(
  sessionRootPath: string,
): ExecutionMetrics | null {
  const path = metricsPath(sessionRootPath);
  if (!existsSync(path)) return null;

  try {
    const parsed = JSON.parse(readFileSync(path, "utf-8")) as Partial<{
      tokenUsage: Partial<TokenUsageTotals>;
      contextUsage?: unknown;
      runtime: string;
      elapsedSeconds: number;
      updatedAt: string;
    }>;

    return {
      tokenUsage: normalizeTokenUsage(parsed.tokenUsage),
      contextUsage: normalizeContextUsage(parsed.contextUsage),
      runtime: typeof parsed.runtime === "string" ? parsed.runtime : undefined,
      elapsedSeconds: toNonNegativeInteger(parsed.elapsedSeconds) || undefined,
      updatedAt:
        typeof parsed.updatedAt === "string"
          ? parsed.updatedAt
          : new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

function writeSessionJsonTokenTotals(
  sessionRootPath: string,
  tokenUsage: TokenUsageTotals,
): void {
  const path = sessionJsonPath(sessionRootPath);
  if (!existsSync(path)) return;

  try {
    const parsed = JSON.parse(readFileSync(path, "utf-8")) as Record<
      string,
      unknown
    >;
    parsed.tokensIn = tokenUsage.inputTokens;
    parsed.tokensOut = tokenUsage.outputTokens;
    writeFileSync(path, JSON.stringify(parsed, null, 2));
  } catch {
    // Best effort: metrics should never break the main execution path.
  }
}

export function writeExecutionMetrics(
  input: WriteExecutionMetricsInput,
): ExecutionMetrics {
  const existing = readExecutionMetrics(input.sessionRootPath);
  const nextTokenUsage = input.tokenUsage
    ? normalizeTokenUsage(input.tokenUsage)
    : (existing?.tokenUsage ?? {
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        totalTokens: 0,
      });

  const next: ExecutionMetrics = {
    tokenUsage: nextTokenUsage,
    contextUsage: input.contextUsage ?? existing?.contextUsage,
    runtime: input.runtime ?? existing?.runtime,
    elapsedSeconds: input.elapsedSeconds ?? existing?.elapsedSeconds,
    updatedAt: new Date().toISOString(),
  };

  writeFileSync(
    metricsPath(input.sessionRootPath),
    JSON.stringify(next, null, 2),
    "utf-8",
  );
  writeSessionJsonTokenTotals(input.sessionRootPath, next.tokenUsage);

  return next;
}

export function formatDurationHmsFromMs(durationMs: number): string {
  const totalSeconds = Math.max(0, Math.floor(durationMs / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `${hours}h${minutes}m${seconds}s`;
}
