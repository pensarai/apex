import { describe, expect, it } from "vitest";
import {
  projectAttemptCacheMetrics,
  projectAttemptUsage,
  startInferenceAttempt,
} from "./index";

const handle = () =>
  startInferenceAttempt({
    operationKind: "structured.generate",
    requested: {
      provider: "pensar",
      modelId: "pensar:anthropic.claude-haiku-4-5",
    },
  });

describe("projectAttemptUsage", () => {
  it("coerces unknown token fields to zero for #1002 consumers", () => {
    const envelope = handle().fail();
    expect(projectAttemptUsage(envelope)).toEqual({
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
    expect(projectAttemptCacheMetrics(envelope)).toBeNull();
  });

  it("projects inclusive input and cache onto the usage-callback shape", () => {
    const envelope = handle().complete({
      transport: "anthropic-messages",
      usage: {
        input_tokens: 100,
        output_tokens: 9,
        cache_read_input_tokens: 900,
        cache_creation_input_tokens: 20,
      },
    });
    expect(projectAttemptUsage(envelope)).toEqual({
      inputTokens: 1020,
      outputTokens: 9,
      cacheReadTokens: 900,
      cacheWriteTokens: 20,
    });
    expect(projectAttemptCacheMetrics(envelope)).toEqual({
      cacheReadInputTokens: 900,
      cacheCreationInputTokens: 20,
    });
  });

  it("reconstructs inclusive input from known uncached when cache is omitted", () => {
    const envelope = handle().complete({
      transport: "anthropic-messages",
      usage: {
        input_tokens: 1000,
        output_tokens: 50,
      },
    });
    expect(envelope.tokens).toEqual({
      inclusiveInput: null,
      uncachedInput: 1000,
      cacheRead: null,
      cacheWrite: null,
      output: 50,
    });
    expect(projectAttemptUsage(envelope)).toEqual({
      inputTokens: 1000,
      outputTokens: 50,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
  });

  it("adds known cache onto uncached when reconstructing inclusive input", () => {
    const envelope = handle().complete({
      tokens: {
        inclusiveInput: null,
        uncachedInput: 100,
        cacheRead: 900,
        cacheWrite: null,
        output: 9,
      },
    });
    expect(projectAttemptUsage(envelope).inputTokens).toBe(1000);
  });

  it("does not invent inclusive input from cache-only counts", () => {
    const envelope = handle().complete({
      tokens: {
        inclusiveInput: null,
        uncachedInput: null,
        cacheRead: 800,
        cacheWrite: null,
        output: 4,
      },
    });
    expect(projectAttemptUsage(envelope)).toEqual({
      inputTokens: 0,
      outputTokens: 4,
      cacheReadTokens: 800,
      cacheWriteTokens: 0,
    });
  });

  it("does not emit CacheMetrics when cache is a reported zero", () => {
    const envelope = handle().complete({
      tokens: {
        inclusiveInput: 10,
        uncachedInput: 10,
        cacheRead: 0,
        cacheWrite: 0,
        output: 1,
      },
    });
    expect(projectAttemptCacheMetrics(envelope)).toBeNull();
    expect(projectAttemptUsage(envelope).cacheReadTokens).toBe(0);
  });
});
