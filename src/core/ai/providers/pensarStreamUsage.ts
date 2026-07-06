import type { LanguageModelV3Usage } from "@ai-sdk/provider";

/** Mutable usage counters accumulated from Anthropic SSE events. */
export interface AnthropicStreamUsageState {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheCreationTokens: number;
}

export function createEmptyStreamUsage(): AnthropicStreamUsageState {
  return {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheCreationTokens: 0,
  };
}

/**
 * Apply usage fields from a `message_start` or `message_delta` event.
 *
 * Anthropic streaming usage is cumulative within a message — values in
 * `message_delta` replace (not add to) those from `message_start`.
 *
 * @see https://platform.claude.com/docs/en/build-with-claude/streaming
 */
export function applyAnthropicStreamUsage(
  state: AnthropicStreamUsageState,
  usage: Record<string, number> | undefined,
): void {
  if (!usage) return;
  if (usage.input_tokens != null) state.inputTokens = usage.input_tokens;
  if (usage.cache_read_input_tokens != null) {
    state.cacheReadTokens = usage.cache_read_input_tokens;
  }
  if (usage.cache_creation_input_tokens != null) {
    state.cacheCreationTokens = usage.cache_creation_input_tokens;
  }
  if (usage.output_tokens != null) state.outputTokens = usage.output_tokens;
}

export function toLanguageModelV3Usage(
  state: AnthropicStreamUsageState,
): LanguageModelV3Usage {
  const { inputTokens, outputTokens, cacheReadTokens, cacheCreationTokens } =
    state;

  return {
    inputTokens: {
      total: inputTokens + cacheReadTokens + cacheCreationTokens,
      noCache: inputTokens,
      cacheRead: cacheReadTokens || undefined,
      cacheWrite: cacheCreationTokens || undefined,
    },
    outputTokens: {
      total: outputTokens,
      text: undefined,
      reasoning: undefined,
    },
  };
}
