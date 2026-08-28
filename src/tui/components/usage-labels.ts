import {
  type ContextUsage,
  contextPercentage,
  type SessionTokenUsage,
} from "../../core/session/usage";

// ---------------------------------------------------------------------------
// Usage footer labels — pure formatting for the token/context display:
//   wide:    in 123k  out 18k  cached 90k  |  context 42% / 200k
//   narrow:  141k tokens  |  42% / 200k
// Cache-read tokens are already part of input and are never added again;
// cache-write tokens stay persisted but are not displayed. The context
// percentage uses the latest root call's sample — its limit comes from the
// model that call ran on, not the currently selected model — and stays
// hidden until a root step has completed.
// ---------------------------------------------------------------------------

const WIDE_MIN_WIDTH = 86;
const NARROW_MIN_WIDTH = 56;

export function formatTokenCount(count: number): string {
  if (count >= 1_000_000) {
    const v = count / 1_000_000;
    return `${Number.isInteger(v) ? v.toFixed(0) : v.toFixed(1)}m`;
  }
  if (count >= 1000) {
    const v = count / 1000;
    return `${Number.isInteger(v) ? v.toFixed(0) : v.toFixed(1)}k`;
  }
  return count.toString();
}

export interface UsageFooterLabels {
  /** Null when the terminal is too narrow to show anything. */
  tokensLabel: string | null;
  /** Null until a root step has completed (no sample) or too narrow. */
  contextLabel: string | null;
}

export function buildUsageFooterLabels(input: {
  tokenUsage: SessionTokenUsage;
  contextUsage: ContextUsage | null;
  width: number;
}): UsageFooterLabels {
  const { tokenUsage, contextUsage, width } = input;
  if (width < NARROW_MIN_WIDTH) {
    return { tokensLabel: null, contextLabel: null };
  }

  if (width >= WIDE_MIN_WIDTH) {
    let tokensLabel = `in ${formatTokenCount(tokenUsage.inputTokens)}  out ${formatTokenCount(tokenUsage.outputTokens)}`;
    if (tokenUsage.cacheReadTokens > 0) {
      tokensLabel += `  cached ${formatTokenCount(tokenUsage.cacheReadTokens)}`;
    }
    // Cache is already inside input; the total is in + out.
    return {
      tokensLabel,
      contextLabel: contextLabel(contextUsage, true),
    };
  }

  const total = tokenUsage.inputTokens + tokenUsage.outputTokens;
  return {
    tokensLabel: `${formatTokenCount(total)} tokens`,
    contextLabel: contextLabel(contextUsage, false),
  };
}

function contextLabel(
  context: ContextUsage | null,
  wide: boolean,
): string | null {
  const percentage = contextPercentage(context);
  if (percentage === null || !context) return null;
  const pct = Math.floor(percentage);
  const limit = formatTokenCount(context.contextLimit);
  return wide ? `context ${pct}% / ${limit}` : `${pct}% / ${limit}`;
}
