import { existsSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";

export const EXECUTION_METRICS_FILENAME = "execution-metrics.json";

interface TokenUsageTotals {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export interface ExecutionMetrics {
  tokenUsage: TokenUsageTotals;
  runtime?: string;
  /** Accumulated wall-clock seconds the pentest has been actively running. */
  elapsedSeconds?: number;
  updatedAt: string;
}

interface WriteExecutionMetricsInput {
  sessionRootPath: string;
  tokenUsage?: Partial<TokenUsageTotals>;
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
    totalTokens: explicitTotal > 0 ? explicitTotal : derivedTotal,
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
      runtime: string;
      elapsedSeconds: number;
      updatedAt: string;
    }>;

    return {
      tokenUsage: normalizeTokenUsage(parsed.tokenUsage),
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
        totalTokens: 0,
      });

  const next: ExecutionMetrics = {
    tokenUsage: nextTokenUsage,
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
