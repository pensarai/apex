import { describe, expect, it } from "vitest";
import type { GatewayStepCost, ReferenceTokenRates } from "./gatewayCost";
import { computeSummary, computeTokenMetrics } from "./runner";
import type { BenchmarkRunResult } from "./types";

const rates: ReferenceTokenRates = {
  inputPerMillion: 1.4,
  outputPerMillion: 4.4,
  cacheReadPerMillion: 0.26,
  cacheWritePerMillion: 0,
  capturedAt: "2026-09-28T00:00:00.000Z",
  source: "test",
};

const stepCost: GatewayStepCost = {
  gateway: "openrouter",
  providerCostUsd: 0.8,
  byok: false,
  servedModel: "z-ai/glm-5.3",
  routes: ["Z.ai"],
  inputTokens: 1_000_000,
  outputTokens: 100_000,
  reasoningTokens: 50_000,
  cacheReadTokens: 200_000,
  cacheWriteTokens: 0,
  referenceCostUsd: 1.612,
};

describe("computeTokenMetrics", () => {
  it("uses provider-billed and reference costs instead of Sonnet constants", () => {
    const metrics = computeTokenMetrics(
      {
        inputTokens: 1_000_000,
        outputTokens: 100_000,
        totalTokens: 1_100_000,
      },
      { cacheReadTokens: 200_000, cacheWriteTokens: 0 },
      5_000,
      [stepCost],
      rates,
    );

    expect(metrics).toMatchObject({
      providerCostUsd: 0.8,
      referenceCostUsd: 1.612,
      routes: ["Z.ai"],
      servedModels: ["z-ai/glm-5.3"],
      byok: false,
    });
    expect(metrics.referenceCostWithoutCacheUsd).toBeCloseTo(1.84);
  });

  it("marks cost unavailable when cost tracking is disabled", () => {
    expect(
      computeTokenMetrics(
        { inputTokens: 10, outputTokens: 2, totalTokens: 12 },
        { cacheReadTokens: 0, cacheWriteTokens: 0 },
        10,
        [],
      ),
    ).toMatchObject({
      providerCostUsd: null,
      referenceCostUsd: null,
      referenceCostWithoutCacheUsd: null,
    });
  });
});

describe("computeSummary", () => {
  it("sums only tracked costs and preserves quality metrics", () => {
    const tokenMetrics = computeTokenMetrics(
      {
        inputTokens: 1_000_000,
        outputTokens: 100_000,
        totalTokens: 1_100_000,
      },
      { cacheReadTokens: 200_000, cacheWriteTokens: 0 },
      5_000,
      [stepCost],
      rates,
    );
    const result: BenchmarkRunResult = {
      branch: "APEX-005-25",
      metadata: null,
      status: "success",
      flagDetected: true,
      flagValue: "flag",
      findingsCount: 1,
      comparisonResult: null,
      tokenMetrics,
      sessionPath: "/tmp/session",
      duration: 5_000,
    };

    const summary = computeSummary([result], Date.now());
    expect(summary).toMatchObject({
      total: 1,
      passed: 1,
      flagCaptureRate: 1,
      totalProviderCostUsd: 0.8,
      totalReferenceCostUsd: 1.612,
    });
    expect(summary.totalReferenceCostWithoutCacheUsd).toBeCloseTo(1.84);
  });
});
