// ---------------------------------------------------------------------------
// Session usage models — pure accounting for a session's token usage:
// cumulative session totals (input/output/cache), the latest root context
// sample, and context-percentage math. No I/O, no React, no event sources.
// ---------------------------------------------------------------------------

/** Cumulative token usage for one session across all runs and agents. */
export interface SessionTokenUsage {
  inputTokens: number;
  outputTokens: number;
  /** Cache-read tokens (Anthropic prompt caching). Already included in inputTokens. */
  cacheReadTokens: number;
  /** Cache-write tokens (Anthropic prompt caching). */
  cacheWriteTokens: number;
}

export const EMPTY_SESSION_TOKEN_USAGE: SessionTokenUsage = {
  inputTokens: 0,
  outputTokens: 0,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
};

/**
 * The latest root-call context sample. Subagent calls never replace this —
 * they run in their own short-lived contexts that say nothing about the
 * operator's conversation size.
 */
export interface ContextUsage {
  usedTokens: number;
  contextLimit: number;
  /** The model the root call actually ran on (the denominator's source). */
  modelId: string;
}

/**
 * Add one step's usage to a session's cumulative totals. Cache-read tokens
 * are already part of the provider's inputTokens, so they accumulate into
 * their own counters and are never added into inputTokens.
 */
export function accumulateSessionTokens(
  current: SessionTokenUsage,
  step: {
    inputTokens?: number;
    outputTokens?: number;
    cacheReadTokens?: number;
    cacheWriteTokens?: number;
  },
): SessionTokenUsage {
  const inputTokens = step.inputTokens ?? 0;
  const outputTokens = step.outputTokens ?? 0;
  const cacheReadTokens = step.cacheReadTokens ?? 0;
  const cacheWriteTokens = step.cacheWriteTokens ?? 0;
  if (
    inputTokens === 0 &&
    outputTokens === 0 &&
    cacheReadTokens === 0 &&
    cacheWriteTokens === 0
  ) {
    return current;
  }
  return {
    inputTokens: current.inputTokens + inputTokens,
    outputTokens: current.outputTokens + outputTokens,
    cacheReadTokens: current.cacheReadTokens + cacheReadTokens,
    cacheWriteTokens: current.cacheWriteTokens + cacheWriteTokens,
  };
}

/**
 * Record the latest root-call context sample. Replacement, not accumulation:
 * each root step's input reflects the whole conversation as the model saw
 * it, so the newest sample *is* the current context size.
 */
export function replaceRootContextUsage(
  modelId: string,
  usedTokens: number,
  contextLimit: number,
): ContextUsage {
  return {
    modelId,
    usedTokens: Math.max(0, usedTokens),
    contextLimit: Math.max(0, contextLimit),
  };
}

/**
 * Percentage of the context window in use, clamped to [0, 100]. Returns null
 * when there is no sample or no usable limit (zero limits never divide).
 */
export function contextPercentage(context: ContextUsage | null): number | null {
  if (!context) return null;
  if (context.contextLimit <= 0) return null;
  const raw = (context.usedTokens / context.contextLimit) * 100;
  return Math.min(100, Math.max(0, raw));
}

/** Total session tokens (input + output). Cache is already inside input. */
export function sessionTokenTotal(usage: SessionTokenUsage): number {
  return usage.inputTokens + usage.outputTokens;
}

/**
 * Hydrate usage from a persisted shape, tolerating legacy files that lack
 * cache or context fields.
 */
export function hydrateSessionUsage(parsed: {
  tokenUsage?: Partial<SessionTokenUsage>;
  contextUsage?: Partial<ContextUsage> | null;
}): { tokenUsage: SessionTokenUsage; contextUsage: ContextUsage | null } {
  const t = parsed.tokenUsage ?? {};
  const tokenUsage: SessionTokenUsage = {
    inputTokens: nonNeg(t.inputTokens),
    outputTokens: nonNeg(t.outputTokens),
    cacheReadTokens: nonNeg(t.cacheReadTokens),
    cacheWriteTokens: nonNeg(t.cacheWriteTokens),
  };
  const c = parsed.contextUsage;
  const contextUsage: ContextUsage | null =
    c && typeof c.modelId === "string" && c.modelId.length > 0
      ? {
          modelId: c.modelId,
          usedTokens: nonNeg(c.usedTokens),
          contextLimit: nonNeg(c.contextLimit),
        }
      : null;
  return { tokenUsage, contextUsage };
}

function nonNeg(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}
