import { describe, expect, it } from "vitest";
import {
  accumulateSessionTokens,
  contextPercentage,
  EMPTY_SESSION_TOKEN_USAGE,
} from "./usage";

// ---------------------------------------------------------------------------
// accumulateSessionTokens
// ---------------------------------------------------------------------------

describe("accumulateSessionTokens", () => {
  it("accumulates input, output, and cache counters across steps", () => {
    let usage = EMPTY_SESSION_TOKEN_USAGE;
    usage = accumulateSessionTokens(usage, {
      inputTokens: 100,
      outputTokens: 20,
      cacheReadTokens: 80,
      cacheWriteTokens: 10,
    });
    usage = accumulateSessionTokens(usage, {
      inputTokens: 50,
      outputTokens: 5,
      cacheReadTokens: 40,
    });

    expect(usage).toEqual({
      inputTokens: 150,
      outputTokens: 25,
      cacheReadTokens: 120,
      cacheWriteTokens: 10,
    });
  });

  it("does not double-count cache reads into input tokens", () => {
    // Anthropic reports cache-read tokens as part of inputTokens; the model
    // keeps them separate here so the footer can show both without summing
    // them twice.
    const usage = accumulateSessionTokens(EMPTY_SESSION_TOKEN_USAGE, {
      inputTokens: 1000,
      cacheReadTokens: 900,
    });
    expect(usage.inputTokens).toBe(1000);
  });

  it("returns the identical reference for an all-zero step", () => {
    const usage = {
      inputTokens: 5,
      outputTokens: 6,
      cacheReadTokens: 7,
      cacheWriteTokens: 8,
    };
    expect(accumulateSessionTokens(usage, {})).toBe(usage);
    expect(
      accumulateSessionTokens(usage, {
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
      }),
    ).toBe(usage);
  });

  it("treats absent optional fields as zero", () => {
    const usage = accumulateSessionTokens(EMPTY_SESSION_TOKEN_USAGE, {
      inputTokens: 10,
    });
    expect(usage).toEqual({
      inputTokens: 10,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
  });
});

// ---------------------------------------------------------------------------
// contextPercentage
// ---------------------------------------------------------------------------

describe("contextPercentage", () => {
  it("computes the percentage of the sampled context limit", () => {
    const sample = { modelId: "m", usedTokens: 84_000, contextLimit: 200_000 };
    expect(contextPercentage(sample)).toBe(42);
  });

  it("clamps above 100 and below 0", () => {
    const over = { modelId: "m", usedTokens: 300_000, contextLimit: 200_000 };
    expect(contextPercentage(over)).toBe(100);
    const under = { modelId: "m", usedTokens: 0, contextLimit: 200_000 };
    expect(contextPercentage(under)).toBe(0);
  });

  it("returns null for no sample and for zero limits", () => {
    expect(contextPercentage(null)).toBeNull();
    const zeroLimit = { modelId: "m", usedTokens: 100, contextLimit: 0 };
    expect(contextPercentage(zeroLimit)).toBeNull();
  });
});
