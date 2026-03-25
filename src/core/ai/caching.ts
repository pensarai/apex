import type { ModelMessage } from "ai";

const ANTHROPIC_CACHE_CONTROL = {
  anthropic: { cacheControl: { type: "ephemeral" as const } },
};

/**
 * Prepend a system message with cache_control to the messages array.
 * This ensures tools + system prompt are cached on every request.
 *
 * The system prompt is placed as a system-role message at the start of
 * the messages array with providerOptions containing cacheControl,
 * so Anthropic caches the entire prefix (tools + system) and reads
 * it from cache on subsequent turns (~90% cost reduction).
 */
export function withCachedSystemPrompt(
  system: string,
  messages: ModelMessage[],
): ModelMessage[] {
  return [
    {
      role: "system" as const,
      content: system,
      providerOptions: ANTHROPIC_CACHE_CONTROL,
    },
    ...messages,
  ];
}

/**
 * Add cache_control to the last message for incremental conversation caching.
 * On each turn, everything up to (and including) the last message is read from cache,
 * so only the new content after the cache breakpoint is billed at full price.
 */
export function withCachedLastMessage(
  messages: ModelMessage[],
): ModelMessage[] {
  if (messages.length === 0) return messages;

  return messages.map((msg, i) => {
    if (i === messages.length - 1) {
      return {
        ...msg,
        providerOptions: {
          ...msg.providerOptions,
          ...ANTHROPIC_CACHE_CONTROL,
        },
      };
    }
    return msg;
  });
}
