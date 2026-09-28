import { describe, expect, it } from "vitest";
import {
  type ArgusProviderComparison,
  generateArgusProviderComparisonMarkdown,
  summarizeArgusProvider,
} from "./argusProviderComparison";
import type {
  BenchmarkRunResult,
  BenchmarkSuiteResult,
  TokenMetrics,
} from "./types";

function tokenMetrics(cost: number, route: string): TokenMetrics {
  return {
    inputTokens: 1_000_000,
    outputTokens: 100_000,
    totalTokens: 1_100_000,
    cacheReadTokens: 200_000,
    cacheWriteTokens: 0,
    noCacheInputTokens: 800_000,
    providerCostUsd: cost,
    referenceCostUsd: 1.612,
    referenceCostWithoutCacheUsd: 1.84,
    routes: [route],
    servedModels: ["glm-5.3"],
    byok: false,
    durationMs: 60_000,
  };
}

function run(
  branch: string,
  cost: number,
  route: string,
  flagDetected: boolean,
): BenchmarkRunResult {
  return {
    branch,
    metadata: null,
    status: "success",
    flagDetected,
    flagValue: flagDetected ? "flag" : null,
    findingsCount: flagDetected ? 2 : 1,
    comparisonResult: null,
    tokenMetrics: tokenMetrics(cost, route),
    sessionPath: `/tmp/${branch}`,
    duration: 60_000,
  };
}

function suite(
  model: string,
  route: string,
  costs: [number, number],
): BenchmarkSuiteResult {
  const results = [
    run("APEX-050-25", costs[0], route, true),
    run("APEX-051-25", costs[1], route, false),
  ];
  return {
    results,
    summary: {
      total: 2,
      passed: 2,
      failed: 0,
      timedOut: 0,
      flagCaptureRate: 0.5,
      vulnDetectionRate: 0,
      avgPrecision: 0,
      avgRecall: 0,
      totalDurationMinutes: 2,
      totalInputTokens: 2_000_000,
      totalOutputTokens: 200_000,
      totalCacheReadTokens: 400_000,
      totalCacheWriteTokens: 0,
      totalProviderCostUsd: costs[0] + costs[1],
      totalReferenceCostUsd: 3.224,
      totalReferenceCostWithoutCacheUsd: 3.68,
      cacheHitRate: 0.2,
    },
    timestamp: "2026-09-28T00:00:00.000Z",
    model,
    repoUrl: "https://example.test/argus",
    fastStrike: true,
  };
}

describe("Argus provider comparison", () => {
  const comparison: ArgusProviderComparison = {
    openrouter: suite("z-ai/glm-5.3", "Z.AI", [2, 3]),
    concentrate: suite("concentrate:glm-5.3", "fireworks/glm-5.3", [1.5, 2]),
    perRunBudgetUsd: 25,
  };

  it("summarizes spend, performance, outcomes, and routes", () => {
    expect(summarizeArgusProvider(comparison.openrouter)).toMatchObject({
      runs: 2,
      completed: 2,
      flagsCaptured: 1,
      findings: 3,
      providerCostUsd: 5,
      costPerFlagUsd: 5,
      routes: ["Z.AI"],
    });
  });

  it("renders fast-strike and per-benchmark results", () => {
    const markdown = generateArgusProviderComparisonMarkdown(comparison);
    expect(markdown).toContain("Mode: Fast Strike");
    expect(markdown).toContain("APEX-050-25");
    expect(markdown).toContain("fireworks/glm-5.3");
    expect(markdown).toContain("Maximum configured spend: $100.0000");
  });
});
