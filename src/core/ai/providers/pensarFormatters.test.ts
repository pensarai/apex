import type { LanguageModelV3CallOptions } from "@ai-sdk/provider";
import { describe, expect, it } from "vitest";
import { convertToBedrockFormat } from "./pensarFormatters";

// Opus 4.6 supports ONLY the 5-minute TTL on Bedrock; the 4.5 generation
// (Opus/Sonnet/Haiku 4.5) additionally supports the extended 1-hour TTL.
const MODEL_ID = "anthropic.claude-opus-4-6-v1";
const MODEL_ID_1H = "anthropic.claude-sonnet-4-5-20250929-v1:0";
const EPHEMERAL = { type: "ephemeral" };
const EPHEMERAL_1H = { type: "ephemeral", ttl: "1h" };
const CACHE_OPTS = { anthropic: { cacheControl: { type: "ephemeral" } } };

type Block = Record<string, unknown>;
type Msg = { role: string; content: string | Block[] };

/** Build a Bedrock request body from a loosely-typed prompt array. */
function build(
  prompt: unknown[],
  modelId: string = MODEL_ID,
): Record<string, unknown> {
  return convertToBedrockFormat(modelId, {
    prompt,
  } as unknown as LanguageModelV3CallOptions);
}

function toolResult(toolCallId: string, value: string): Block {
  return {
    type: "tool-result",
    toolCallId,
    toolName: "http_request",
    output: { type: "text", value },
  };
}

/** Content blocks of the message at `index` (defaults to the last message). */
function blocksOf(body: Record<string, unknown>, index = -1): Block[] {
  const messages = body.messages as Msg[];
  const msg = messages.at(index);
  return msg?.content as Block[];
}

describe("convertToBedrockFormat — Anthropic cache_control", () => {
  it("tags the last tool_result block when the tool message carries cacheControl (fix #1)", () => {
    // In an agent loop the rolling breakpoint (withCachedLastMessage) lands on
    // the trailing tool result. Previously the tool branch ignored it, so only
    // the static system block ever cached.
    const body = build([
      {
        role: "tool",
        providerOptions: CACHE_OPTS,
        content: [toolResult("call_1", "RESPONSE BODY")],
      },
    ]);

    expect((body.messages as Msg[]).at(-1)?.role).toBe("user");
    const lastBlock = blocksOf(body).at(-1);
    expect(lastBlock?.type).toBe("tool_result");
    expect(lastBlock?.cache_control).toEqual(EPHEMERAL);
  });

  it("tags only the LAST tool_result block when several are present", () => {
    const body = build([
      {
        role: "tool",
        providerOptions: CACHE_OPTS,
        content: [toolResult("a", "first"), toolResult("b", "second")],
      },
    ]);

    const blocks = blocksOf(body);
    expect(blocks.at(0)?.cache_control).toBeUndefined();
    expect(blocks.at(1)?.cache_control).toEqual(EPHEMERAL);
  });

  it("does NOT tag tool results when no cacheControl is present (regression guard)", () => {
    const body = build([
      {
        role: "tool",
        content: [toolResult("call_1", "RESPONSE BODY")],
      },
    ]);

    expect(blocksOf(body).at(0)?.cache_control).toBeUndefined();
  });

  it("applies a 1-hour TTL to the cached system prefix on a model that supports it (fix #3)", () => {
    const body = build(
      [
        {
          role: "system",
          content: "SYSTEM PROMPT",
          providerOptions: CACHE_OPTS,
        },
      ],
      MODEL_ID_1H,
    );

    expect(body.system).toEqual([
      { type: "text", text: "SYSTEM PROMPT", cache_control: EPHEMERAL_1H },
    ]);
  });

  it("uses 5-minute ephemeral (no ttl) for the system prefix on Opus 4.6, which lacks 1h support", () => {
    const body = build([
      { role: "system", content: "SYSTEM PROMPT", providerOptions: CACHE_OPTS },
    ]);

    expect(body.system).toEqual([
      { type: "text", text: "SYSTEM PROMPT", cache_control: EPHEMERAL },
    ]);
  });

  it("keeps the system prompt a plain string when uncached", () => {
    const body = build([{ role: "system", content: "SYSTEM PROMPT" }]);
    expect(body.system).toBe("SYSTEM PROMPT");
  });
});
