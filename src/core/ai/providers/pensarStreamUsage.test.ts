import { describe, expect, it } from "vitest";
import {
  applyAnthropicStreamUsage,
  createEmptyStreamUsage,
  toLanguageModelV3Usage,
} from "./pensarStreamUsage";

describe("applyAnthropicStreamUsage", () => {
  it("captures cache write from message_start (turn 1)", () => {
    const state = createEmptyStreamUsage();
    applyAnthropicStreamUsage(state, {
      input_tokens: 3,
      cache_creation_input_tokens: 24_542,
      cache_read_input_tokens: 0,
      output_tokens: 1,
    });
    expect(state).toEqual({
      inputTokens: 3,
      outputTokens: 1,
      cacheReadTokens: 0,
      cacheCreationTokens: 24_542,
    });
  });

  it("captures cache read from message_delta (turn 2+)", () => {
    const state = createEmptyStreamUsage();
    // message_start — cache read often 0 at stream open
    applyAnthropicStreamUsage(state, {
      input_tokens: 45,
      cache_creation_input_tokens: 944,
      cache_read_input_tokens: 0,
      output_tokens: 1,
    });
    // message_delta — final cumulative usage includes cache read
    applyAnthropicStreamUsage(state, {
      input_tokens: 45,
      cache_creation_input_tokens: 944,
      cache_read_input_tokens: 24_000,
      output_tokens: 125,
    });
    expect(state.cacheReadTokens).toBe(24_000);
    expect(state.cacheCreationTokens).toBe(944);
    expect(state.outputTokens).toBe(125);
  });

  it("replaces cumulative values rather than summing across events", () => {
    const state = createEmptyStreamUsage();
    applyAnthropicStreamUsage(state, {
      input_tokens: 100,
      cache_read_input_tokens: 1_000,
      cache_creation_input_tokens: 500,
    });
    applyAnthropicStreamUsage(state, {
      input_tokens: 100,
      cache_read_input_tokens: 1_000,
      cache_creation_input_tokens: 500,
      output_tokens: 50,
    });
    expect(state.cacheReadTokens).toBe(1_000);
    expect(state.cacheCreationTokens).toBe(500);
    expect(state.outputTokens).toBe(50);
  });

  it("maps to LanguageModelV3Usage with separate buckets", () => {
    const state = createEmptyStreamUsage();
    applyAnthropicStreamUsage(state, {
      input_tokens: 45,
      cache_read_input_tokens: 24_000,
      cache_creation_input_tokens: 944,
      output_tokens: 125,
    });
    const usage = toLanguageModelV3Usage(state);
    expect(usage.inputTokens.noCache).toBe(45);
    expect(usage.inputTokens.cacheRead).toBe(24_000);
    expect(usage.inputTokens.cacheWrite).toBe(944);
    expect(usage.inputTokens.total).toBe(45 + 24_000 + 944);
    expect(usage.outputTokens.total).toBe(125);
  });
});
