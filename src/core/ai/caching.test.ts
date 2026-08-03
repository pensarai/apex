import type { ModelMessage } from "ai";
import { describe, expect, it } from "vitest";
import {
  cacheBreakpointFor,
  withCachedLastMessage,
  withCachedSystemPrompt,
} from "./caching";

const BEDROCK_BREAKPOINT = { bedrock: { cachePoint: { type: "default" } } };
const ANTHROPIC_BREAKPOINT = {
  anthropic: { cacheControl: { type: "ephemeral" } },
};

describe("cacheBreakpointFor", () => {
  it.each([
    "global.anthropic.claude-opus-4-6-v1",
    "global.anthropic.claude-opus-4-8",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
    "anthropic.claude-sonnet-4-6-v1",
    "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
    "us.anthropic.claude-3-5-haiku-20241022-v1:0",
  ])("uses the bedrock cachePoint namespace for %s", (model) => {
    expect(cacheBreakpointFor(model)).toEqual(BEDROCK_BREAKPOINT);
  });

  it("never emits an anthropic key on Bedrock", () => {
    // The bug this guards: @ai-sdk/amazon-bedrock only reads
    // providerOptions.bedrock.cachePoint, so an `anthropic` key is dropped with
    // no error and every request bills the full prefix.
    expect(
      cacheBreakpointFor("global.anthropic.claude-opus-4-6-v1"),
    ).not.toHaveProperty("anthropic");
  });

  it.each([
    "us.deepseek.r1-v1:0",
    "us.amazon.nova-lite-v1:0",
    "amazon.titan-text-express-v1",
    "anthropic.claude-v2",
    "anthropic.claude-v2:1",
    "anthropic.claude-instant-v1",
    "global.anthropic.claude-3-opus-20240229-v1:0",
    "us.anthropic.claude-3-haiku-20240307-v1:0",
    "anthropic.claude-3-5-sonnet-20240620-v1:0",
    "us.anthropic.claude-3-5-sonnet-20240620-v1:0",
    "global.anthropic.claude-3-5-sonnet-20240620-v1:0",
  ])("returns undefined for Bedrock model %s", (model) => {
    // Bedrock rejects a cache point outright on models that don't support
    // prompt caching, so these must stay uncached rather than 400.
    expect(cacheBreakpointFor(model)).toBeUndefined();
  });

  it("uses the anthropic namespace for direct Anthropic models", () => {
    expect(cacheBreakpointFor("claude-haiku-4-5")).toEqual(
      ANTHROPIC_BREAKPOINT,
    );
  });

  it("uses the anthropic namespace for Pensar gateway models", () => {
    // The gateway hand-builds native Anthropic cache_control blocks — see
    // providers/pensarFormatters.ts.
    expect(cacheBreakpointFor("pensar:anthropic.claude-opus-4-8")).toEqual(
      ANTHROPIC_BREAKPOINT,
    );
  });

  it.each([
    "gpt-5.6-sol",
    "some-unknown-model",
  ])("returns undefined for %s", (model) => {
    expect(cacheBreakpointFor(model)).toBeUndefined();
  });
});

describe("withCachedSystemPrompt", () => {
  const messages: ModelMessage[] = [{ role: "user", content: "hi" }];

  it("prepends a system message carrying the breakpoint", () => {
    const result = withCachedSystemPrompt(
      "be helpful",
      messages,
      BEDROCK_BREAKPOINT,
    );
    expect(result[0]).toEqual({
      role: "system",
      content: "be helpful",
      providerOptions: BEDROCK_BREAKPOINT,
    });
    expect(result.slice(1)).toEqual(messages);
  });

  it("omits providerOptions when the model has no breakpoint", () => {
    const result = withCachedSystemPrompt("be helpful", messages, undefined);
    expect(result[0]).not.toHaveProperty("providerOptions");
  });
});

describe("withCachedLastMessage", () => {
  it("marks only the last message", () => {
    const result = withCachedLastMessage(
      [
        { role: "user", content: "first" },
        { role: "assistant", content: "second" },
        { role: "user", content: "third" },
      ],
      BEDROCK_BREAKPOINT,
    );
    expect(result[0].providerOptions).toBeUndefined();
    expect(result[1].providerOptions).toBeUndefined();
    expect(result[2].providerOptions).toEqual(BEDROCK_BREAKPOINT);
  });

  it("merges with providerOptions already on the message", () => {
    const result = withCachedLastMessage(
      [
        {
          role: "user",
          content: "hi",
          providerOptions: { anthropic: { signature: "abc" } },
        },
      ],
      BEDROCK_BREAKPOINT,
    );
    expect(result[0].providerOptions).toEqual({
      anthropic: { signature: "abc" },
      ...BEDROCK_BREAKPOINT,
    });
  });

  it("keeps sibling options within the same provider namespace", () => {
    const result = withCachedLastMessage(
      [
        {
          role: "user",
          content: "hi",
          providerOptions: { bedrock: { citations: { enabled: true } } },
        },
      ],
      BEDROCK_BREAKPOINT,
    );
    expect(result[0].providerOptions).toEqual({
      bedrock: {
        citations: { enabled: true },
        cachePoint: { type: "default" },
      },
    });
  });

  it("is a no-op without a breakpoint", () => {
    const messages: ModelMessage[] = [{ role: "user", content: "hi" }];
    expect(withCachedLastMessage(messages, undefined)).toBe(messages);
  });

  it("is a no-op on an empty list", () => {
    expect(withCachedLastMessage([], BEDROCK_BREAKPOINT)).toEqual([]);
  });
});
