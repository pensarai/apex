import type { ProviderAttemptEnvelope } from "./envelope";

/**
 * #1002 usage-callback shape. Unknown envelope fields become 0 — the
 * historical "always present" behavior existing consumers still expect.
 */
export interface ProjectedAttemptUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

/**
 * `CacheMetrics` twin (core/ai). Returned only when a known cache field
 * is greater than zero, matching `onCacheMetrics` emission.
 */
export interface ProjectedCacheMetrics {
  cacheReadInputTokens: number;
  cacheCreationInputTokens: number;
}

export function projectAttemptUsage(
  envelope: ProviderAttemptEnvelope,
): ProjectedAttemptUsage {
  return {
    inputTokens: envelope.tokens.inclusiveInput ?? 0,
    outputTokens: envelope.tokens.output ?? 0,
    cacheReadTokens: envelope.tokens.cacheRead ?? 0,
    cacheWriteTokens: envelope.tokens.cacheWrite ?? 0,
  };
}

export function projectAttemptCacheMetrics(
  envelope: ProviderAttemptEnvelope,
): ProjectedCacheMetrics | null {
  const cacheReadInputTokens = envelope.tokens.cacheRead ?? 0;
  const cacheCreationInputTokens = envelope.tokens.cacheWrite ?? 0;
  if (cacheReadInputTokens <= 0 && cacheCreationInputTokens <= 0) {
    return null;
  }
  return { cacheReadInputTokens, cacheCreationInputTokens };
}
