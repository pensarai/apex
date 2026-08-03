import type { ModelMessage } from "ai";
import type { AIModel } from "./ai";
import { getModelInfo } from "./models";

type CacheBreakpoint = NonNullable<ModelMessage["providerOptions"]>;

const ANTHROPIC_CACHE_CONTROL: CacheBreakpoint = {
  anthropic: { cacheControl: { type: "ephemeral" as const } },
};

/**
 * Bedrock's Converse API namespaces the breakpoint under `bedrock.cachePoint`.
 * Provider options are keyed by provider id, so an `anthropic` key is dropped
 * with no error and no warning — which is how caching stayed silently off on
 * every Bedrock model. Confirmed against live Bedrock: `anthropic.cacheControl`
 * reports cacheWrite/cacheRead of 0, `bedrock.cachePoint` caches the prefix.
 */
const BEDROCK_CACHE_POINT: CacheBreakpoint = {
  bedrock: { cachePoint: { type: "default" as const } },
};

/**
 * Bedrock *rejects* a cache point on models that don't support prompt caching
 * ("You invoked an unsupported model or your request did not allow prompt
 * caching" — observed on `us.deepseek.r1-v1:0`), so this is an allowlist rather
 * than best-effort. Models outside it keep running uncached instead of failing.
 */
function bedrockSupportsCachePoint(modelId: string): boolean {
  const base = modelId.replace(/^(?:[a-z]{2,6}\.)?anthropic\./, "");
  return /^claude-(?:3-7-sonnet|sonnet-4|opus-4|haiku-4)/.test(base);
}

/**
 * Provider options marking a cache breakpoint for `model`, or `undefined` when
 * the model has no breakpoint we can express.
 */
export function cacheBreakpointFor(
  model: AIModel,
): CacheBreakpoint | undefined {
  const { provider } = getModelInfo(model);
  switch (provider) {
    case "anthropic":
    // The Pensar gateway speaks the native Anthropic Messages API and reads
    // this same key — see providers/pensarFormatters.ts.
    case "pensar":
      return ANTHROPIC_CACHE_CONTROL;
    case "bedrock":
      return bedrockSupportsCachePoint(model) ? BEDROCK_CACHE_POINT : undefined;
    default:
      return undefined;
  }
}

/**
 * Prepend a system message carrying a cache breakpoint to the messages array.
 * This ensures tools + system prompt are cached on every request.
 *
 * The system prompt is placed as a system-role message at the start of
 * the messages array with providerOptions containing the breakpoint, so the
 * provider caches the entire prefix (tools + system) and reads it from cache
 * on subsequent turns (~90% cost reduction).
 */
export function withCachedSystemPrompt(
  system: string,
  messages: ModelMessage[],
  breakpoint: CacheBreakpoint | undefined,
): ModelMessage[] {
  return [
    {
      role: "system" as const,
      content: system,
      ...(breakpoint ? { providerOptions: breakpoint } : {}),
    },
    ...messages,
  ];
}

/**
 * Add a cache breakpoint to the last message for incremental conversation
 * caching. On each turn, everything up to (and including) the last message is
 * read from cache, so only the new content after the breakpoint is billed at
 * full price.
 */
export function withCachedLastMessage(
  messages: ModelMessage[],
  breakpoint: CacheBreakpoint | undefined,
): ModelMessage[] {
  if (messages.length === 0 || !breakpoint) return messages;

  return messages.map((msg, i) => {
    if (i === messages.length - 1) {
      return {
        ...msg,
        providerOptions: {
          ...msg.providerOptions,
          ...breakpoint,
        },
      };
    }
    return msg;
  });
}
