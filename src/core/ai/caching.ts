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
 * Legacy Claude on Bedrock — v2, instant, and the Claude 3 line — predates
 * prompt caching; 3.5 onward supports it. Kept as a deny-list so a new Claude
 * generation picks caching up the moment `generate:models` adds it, rather than
 * silently losing it again, which is the failure this whole fix is about.
 */
const BEDROCK_UNCACHEABLE_CLAUDE =
  /^claude-(?:v2|instant|3-(?:opus|sonnet|haiku))/;

/**
 * Bedrock *rejects* a cache point on models that don't support prompt caching
 * ("You invoked an unsupported model or your request did not allow prompt
 * caching" — observed on `us.deepseek.r1-v1:0`), so this gate is load-bearing:
 * non-Claude Bedrock models must stay uncached rather than fail.
 */
function bedrockSupportsCachePoint(modelId: string): boolean {
  // Strip the cross-region inference-profile prefix (`global.`, `us.`, `eu.`, …).
  const base = modelId.replace(/^(?:[a-z]{2,6}\.)?anthropic\./, "");
  return base.startsWith("claude-") && !BEDROCK_UNCACHEABLE_CLAUDE.test(base);
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
      // Merge inside the provider's namespace — a top-level spread would drop
      // any sibling options the message already carries for that provider.
      const merged = { ...msg.providerOptions };
      for (const [provider, options] of Object.entries(breakpoint)) {
        merged[provider] = { ...merged[provider], ...options };
      }
      return { ...msg, providerOptions: merged };
    }
    return msg;
  });
}
