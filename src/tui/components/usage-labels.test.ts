import { describe, expect, it } from "vitest";
import type { ContextUsage, SessionTokenUsage } from "../../core/session/usage";
import { buildUsageFooterLabels, formatTokenCount } from "./usage-labels";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const usage: SessionTokenUsage = {
  inputTokens: 123_000,
  outputTokens: 18_000,
  cacheReadTokens: 90_000,
  cacheWriteTokens: 4_000,
};

const context: ContextUsage = {
  usedTokens: 84_000,
  contextLimit: 200_000,
  modelId: "claude-sonnet-4-5",
};

// ---------------------------------------------------------------------------
// formatTokenCount
// ---------------------------------------------------------------------------

describe("formatTokenCount", () => {
  it("uses lowercase k/m units with trailing .0 dropped", () => {
    expect(formatTokenCount(0)).toBe("0");
    expect(formatTokenCount(999)).toBe("999");
    expect(formatTokenCount(1000)).toBe("1k");
    expect(formatTokenCount(123_000)).toBe("123k");
    expect(formatTokenCount(141_500)).toBe("141.5k");
    expect(formatTokenCount(1_000_000)).toBe("1m");
    expect(formatTokenCount(1_200_000)).toBe("1.2m");
    expect(formatTokenCount(200_000)).toBe("200k");
  });
});

// ---------------------------------------------------------------------------
// buildUsageFooterLabels — wide mode
// ---------------------------------------------------------------------------

describe("buildUsageFooterLabels wide", () => {
  it("renders the explicit labeled form", () => {
    const labels = buildUsageFooterLabels({
      tokenUsage: usage,
      contextUsage: context,
      width: 120,
    });
    expect(labels.tokensLabel).toBe("in 123k  out 18k  cached 90k");
    expect(labels.contextLabel).toBe("context 42% / 200k");
  });

  it("omits the cached segment when cache reads are zero", () => {
    const labels = buildUsageFooterLabels({
      tokenUsage: { ...usage, cacheReadTokens: 0 },
      contextUsage: context,
      width: 120,
    });
    expect(labels.tokensLabel).toBe("in 123k  out 18k");
  });

  it("never adds cache tokens into the totals (cache rides inside input)", () => {
    // input 123k includes the 90k cached — the label shows both, no sum.
    const labels = buildUsageFooterLabels({
      tokenUsage: usage,
      contextUsage: context,
      width: 120,
    });
    expect(labels.tokensLabel).toContain("in 123k");
    expect(labels.tokensLabel).toContain("cached 90k");
  });

  it("hides the context segment until a root step has completed", () => {
    const labels = buildUsageFooterLabels({
      tokenUsage: usage,
      contextUsage: null,
      width: 120,
    });
    expect(labels.contextLabel).toBeNull();
    expect(labels.tokensLabel).toBe("in 123k  out 18k  cached 90k");
  });

  it("hides the context segment for a zero-limit sample", () => {
    const labels = buildUsageFooterLabels({
      tokenUsage: usage,
      contextUsage: { usedTokens: 10, contextLimit: 0, modelId: "m" },
      width: 120,
    });
    expect(labels.contextLabel).toBeNull();
  });

  it("floors the percentage and formats the sampled limit", () => {
    const labels = buildUsageFooterLabels({
      tokenUsage: usage,
      contextUsage: {
        usedTokens: 199_999,
        contextLimit: 200_000,
        modelId: "m",
      },
      width: 120,
    });
    expect(labels.contextLabel).toBe("context 99% / 200k");
  });
});

// ---------------------------------------------------------------------------
// buildUsageFooterLabels — narrow mode
// ---------------------------------------------------------------------------

describe("buildUsageFooterLabels narrow", () => {
  it("renders the compact total form", () => {
    const labels = buildUsageFooterLabels({
      tokenUsage: usage,
      contextUsage: context,
      width: 70,
    });
    // 123k in + 18k out; cache is inside input and not added again.
    expect(labels.tokensLabel).toBe("141k tokens");
    expect(labels.contextLabel).toBe("42% / 200k");
  });

  it("hides context with no sample", () => {
    const labels = buildUsageFooterLabels({
      tokenUsage: usage,
      contextUsage: null,
      width: 70,
    });
    expect(labels.tokensLabel).toBe("141k tokens");
    expect(labels.contextLabel).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Width gating
// ---------------------------------------------------------------------------

describe("buildUsageFooterLabels width gating", () => {
  it("hides everything below the narrow threshold", () => {
    const labels = buildUsageFooterLabels({
      tokenUsage: usage,
      contextUsage: context,
      width: 55,
    });
    expect(labels.tokensLabel).toBeNull();
    expect(labels.contextLabel).toBeNull();
  });

  it("narrow at the boundary, wide at the wide boundary", () => {
    const narrow = buildUsageFooterLabels({
      tokenUsage: usage,
      contextUsage: context,
      width: 85,
    });
    expect(narrow.tokensLabel).toBe("141k tokens");
    const wide = buildUsageFooterLabels({
      tokenUsage: usage,
      contextUsage: context,
      width: 86,
    });
    expect(wide.tokensLabel).toBe("in 123k  out 18k  cached 90k");
  });

  it("zero usage still renders token labels (durable totals, honest zeros)", () => {
    const labels = buildUsageFooterLabels({
      tokenUsage: {
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
      },
      contextUsage: null,
      width: 120,
    });
    expect(labels.tokensLabel).toBe("in 0  out 0");
    expect(labels.contextLabel).toBeNull();
  });
});
