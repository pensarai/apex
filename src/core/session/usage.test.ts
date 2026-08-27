import { describe, expect, it } from "vitest";
import {
  accumulateSessionTokens,
  contextPercentage,
  EMPTY_SESSION_TOKEN_USAGE,
  hydrateSessionUsage,
  replaceRootContextUsage,
  sessionTokenTotal,
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
    expect(sessionTokenTotal(usage)).toBe(1000);
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
// replaceRootContextUsage
// ---------------------------------------------------------------------------

describe("replaceRootContextUsage", () => {
  it("replaces rather than accumulates across root steps", () => {
    const first = replaceRootContextUsage("claude-sonnet-4-5", 10_000, 200_000);
    const second = replaceRootContextUsage(
      "claude-sonnet-4-5",
      42_000,
      200_000,
    );

    // The newest sample is the context size — no summation.
    expect(second.usedTokens).toBe(42_000);
    expect(second).not.toEqual(first);
  });

  it("records the model the call ran on, even when it differs from selection", () => {
    const sample = replaceRootContextUsage("gpt-5.2", 10_000, 272_000);
    expect(sample.modelId).toBe("gpt-5.2");
    expect(sample.contextLimit).toBe(272_000);
  });

  it("clamps negative values to zero", () => {
    const sample = replaceRootContextUsage("m", -5, -10);
    expect(sample.usedTokens).toBe(0);
    expect(sample.contextLimit).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// contextPercentage
// ---------------------------------------------------------------------------

describe("contextPercentage", () => {
  it("computes the percentage of the sampled context limit", () => {
    const sample = replaceRootContextUsage("m", 84_000, 200_000);
    expect(contextPercentage(sample)).toBe(42);
  });

  it("clamps above 100 and below 0", () => {
    const over = replaceRootContextUsage("m", 300_000, 200_000);
    expect(contextPercentage(over)).toBe(100);
    const under = replaceRootContextUsage("m", -1, 200_000);
    expect(contextPercentage(under)).toBe(0);
  });

  it("returns null for no sample and for zero limits", () => {
    expect(contextPercentage(null)).toBeNull();
    const zeroLimit = replaceRootContextUsage("m", 100, 0);
    expect(contextPercentage(zeroLimit)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// sessionTokenTotal
// ---------------------------------------------------------------------------

describe("sessionTokenTotal", () => {
  it("sums input and output only — cache rides inside input", () => {
    expect(
      sessionTokenTotal({
        inputTokens: 100,
        outputTokens: 20,
        cacheReadTokens: 90,
        cacheWriteTokens: 5,
      }),
    ).toBe(120);
  });
});

// ---------------------------------------------------------------------------
// hydrateSessionUsage
// ---------------------------------------------------------------------------

describe("hydrateSessionUsage", () => {
  it("hydrates a complete modern shape", () => {
    const { tokenUsage, contextUsage } = hydrateSessionUsage({
      tokenUsage: {
        inputTokens: 100,
        outputTokens: 20,
        cacheReadTokens: 90,
        cacheWriteTokens: 5,
      },
      contextUsage: {
        usedTokens: 42_000,
        contextLimit: 200_000,
        modelId: "claude-sonnet-4-5",
      },
    });

    expect(tokenUsage).toEqual({
      inputTokens: 100,
      outputTokens: 20,
      cacheReadTokens: 90,
      cacheWriteTokens: 5,
    });
    expect(contextUsage).toEqual({
      usedTokens: 42_000,
      contextLimit: 200_000,
      modelId: "claude-sonnet-4-5",
    });
  });

  it("fills missing cache fields from legacy files", () => {
    const { tokenUsage, contextUsage } = hydrateSessionUsage({
      tokenUsage: { inputTokens: 7, outputTokens: 3 },
    });
    expect(tokenUsage).toEqual({
      inputTokens: 7,
      outputTokens: 3,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
    expect(contextUsage).toBeNull();
  });

  it("drops malformed context samples (no model id)", () => {
    const { contextUsage } = hydrateSessionUsage({
      contextUsage: { usedTokens: 10, contextLimit: 200 },
    });
    expect(contextUsage).toBeNull();
  });

  it("sanitizes negative and non-numeric values", () => {
    const { tokenUsage } = hydrateSessionUsage({
      tokenUsage: {
        inputTokens: -5,
        outputTokens: Number("abc"), // NaN - sanitized to 0
        cacheReadTokens: 1.9,
      },
    });
    expect(tokenUsage).toEqual({
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 1,
      cacheWriteTokens: 0,
    });
  });
});
