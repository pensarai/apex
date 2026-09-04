import type { InferenceAttempt } from "./envelope";

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
  envelope: InferenceAttempt,
): ProjectedAttemptUsage {
  return {
    inputTokens: projectInputTokens(envelope),
    outputTokens: envelope.tokens.output ?? 0,
    cacheReadTokens: envelope.tokens.cacheRead ?? 0,
    cacheWriteTokens: envelope.tokens.cacheWrite ?? 0,
  };
}

/**
 * #1002 `inputTokens` is inclusive. When the envelope could not close
 * inclusive (cache keys omitted), reconstruct it from known uncached
 * plus zero-filled cache — do not drop a known uncached total to 0.
 */
function projectInputTokens(envelope: InferenceAttempt): number {
  const { inclusiveInput, uncachedInput, cacheRead, cacheWrite } =
    envelope.tokens;
  if (inclusiveInput !== null) {
    return inclusiveInput;
  }
  if (uncachedInput === null) {
    return 0;
  }
  return uncachedInput + (cacheRead ?? 0) + (cacheWrite ?? 0);
}

export function projectAttemptCacheMetrics(
  envelope: InferenceAttempt,
): ProjectedCacheMetrics | null {
  const cacheReadInputTokens = envelope.tokens.cacheRead ?? 0;
  const cacheCreationInputTokens = envelope.tokens.cacheWrite ?? 0;
  if (cacheReadInputTokens <= 0 && cacheCreationInputTokens <= 0) {
    return null;
  }
  return { cacheReadInputTokens, cacheCreationInputTokens };
}
