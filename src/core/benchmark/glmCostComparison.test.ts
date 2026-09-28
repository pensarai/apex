import { describe, expect, it } from "vitest";
import type { CostBenchResult } from "./costBench";
import {
  type GlmGatewayCostComparison,
  generateGlmGatewayComparisonMarkdown,
  totalComparisonSpend,
} from "./glmCostComparison";
import type { BenchmarkSuiteResult } from "./types";

function argus(
  model: string,
  cost: number,
  route: string,
): BenchmarkSuiteResult {
  return {
    timestamp: "2026-09-28T00:10:00.000Z",
    model,
    repoUrl: "https://example.test/argus",
    results: [
      {
        branch: "APEX-005-25",
        metadata: null,
        status: "success",
        flagDetected: true,
        flagValue: "flag",
        findingsCount: 1,
        comparisonResult: null,
        sessionPath: "/tmp/session",
        duration: 60_000,
        tokenMetrics: {
          inputTokens: 1_000,
          outputTokens: 100,
          totalTokens: 1_100,
          cacheReadTokens: 100,
          cacheWriteTokens: 0,
          noCacheInputTokens: 900,
          providerCostUsd: cost,
          referenceCostUsd: 0.002,
          referenceCostWithoutCacheUsd: 0.002,
          routes: [route],
          servedModels: [model],
          byok: false,
          durationMs: 50_000,
        },
      },
    ],
    summary: {
      total: 1,
      passed: 1,
      failed: 0,
      timedOut: 0,
      flagCaptureRate: 1,
      vulnDetectionRate: 0,
      avgPrecision: 0,
      avgRecall: 0,
      totalDurationMinutes: 1,
      totalInputTokens: 1_000,
      totalOutputTokens: 100,
      totalCacheReadTokens: 100,
      totalCacheWriteTokens: 0,
      totalProviderCostUsd: cost,
      totalReferenceCostUsd: 0.002,
      totalReferenceCostWithoutCacheUsd: 0.002,
      cacheHitRate: 0.1,
    },
  };
}

const micro: CostBenchResult = {
  benchmark: "glm-5.3-gateway-cost",
  startedAt: "2026-09-28T00:00:00.000Z",
  completedAt: "2026-09-28T00:01:00.000Z",
  repetitions: 1,
  budgetUsd: 10,
  spentUsd: 0.03,
  referenceRates: {
    inputPerMillion: 1.4,
    outputPerMillion: 4.4,
    cacheReadPerMillion: 0.26,
    cacheWritePerMillion: 0,
    capturedAt: "2026-09-28T00:00:00.000Z",
    source: "test",
  },
  models: {
    openrouter: "z-ai/glm-5.3",
    concentrate: "concentrate:glm-5.3",
  },
  cases: [],
  samples: [],
};

describe("GLM gateway combined comparison", () => {
  const comparison: GlmGatewayCostComparison = {
    micro,
    argus: {
      branch: "APEX-005-25",
      openrouter: argus("z-ai/glm-5.3", 1.2, "Z.ai"),
      concentrate: argus("concentrate:glm-5.3", 0.9, "fireworks/glm-5.3"),
    },
    budgetUsd: 100,
  };

  it("combines micro and Argus provider spend", () => {
    expect(totalComparisonSpend(comparison)).toBeCloseTo(2.13);
  });

  it("renders Argus quality, cost, routes, and ceiling evidence", () => {
    const markdown = generateGlmGatewayComparisonMarkdown(comparison);
    expect(markdown).toContain("## Argus production-shaped pilot");
    expect(markdown).toContain("| Flag captured | yes | yes |");
    expect(markdown).toContain("fireworks/glm-5.3");
    expect(markdown).toContain("$2.130000 / $100.00");
  });
});
