import { describe, expect, it } from "vitest";
import {
  type CostBenchResult,
  type CostBenchSample,
  validateCostBenchOutput,
} from "./costBench";
import {
  generateCostBenchMarkdown,
  summarizeCostBench,
} from "./costBenchReport";

describe("validateCostBenchOutput", () => {
  it("validates every deterministic case", () => {
    expect(
      validateCostBenchOutput("exact-reasoning", "ANSWER=731", []),
    ).toBeUndefined();
    expect(
      validateCostBenchOutput(
        "structured-extraction",
        '{"account":"ACME-42","risk":"high","ports":[443,8443]}',
        [],
      ),
    ).toBeUndefined();
    expect(
      validateCostBenchOutput("tool-call", "QUOTE=84", [
        {
          name: "quote_cost",
          input: { quantity: 7, unitPrice: 12 },
        },
      ]),
    ).toBeUndefined();
    expect(
      validateCostBenchOutput(
        "security-analysis",
        "FINDINGS=SQL_INJECTION,HARDCODED_SECRET,PLAINTEXT_PASSWORD_LOG",
        [],
      ),
    ).toBeUndefined();
    expect(
      validateCostBenchOutput(
        "long-context-cache",
        "NEEDLE=cobalt-heron-927",
        [],
      ),
    ).toBeUndefined();
  });

  it("rejects plausible but incorrect output", () => {
    expect(
      validateCostBenchOutput("exact-reasoning", "The answer is 731", []),
    ).toMatch(/Expected exactly/);
    expect(
      validateCostBenchOutput(
        "security-analysis",
        "FINDINGS=SQL_INJECTION",
        [],
      ),
    ).toMatch(/three planted/);
  });
});

function sample(
  gateway: "openrouter" | "concentrate",
  overrides: Partial<CostBenchSample> = {},
): CostBenchSample {
  return {
    caseId: "exact-reasoning",
    gateway,
    requestedModel:
      gateway === "openrouter" ? "z-ai/glm-5.3" : "concentrate:glm-5.3",
    repetition: 1,
    status: "passed",
    responseText: "ANSWER=731",
    toolCalls: [],
    servedModels: ["glm-5.3"],
    routes: [gateway === "openrouter" ? "Z.ai" : "zai/glm-5.3"],
    byok: false,
    inputTokens: 100,
    outputTokens: 20,
    reasoningTokens: 10,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    providerCostUsd: gateway === "openrouter" ? 0.01 : 0.008,
    referenceCostUsd: 0.01,
    timeToFirstTokenMs: gateway === "openrouter" ? 200 : 100,
    totalLatencyMs: gateway === "openrouter" ? 1_000 : 800,
    outputTokensPerSecond: gateway === "openrouter" ? 25 : 30,
    stepCount: 1,
    startedAt: "2026-09-28T00:00:00.000Z",
    ...overrides,
  };
}

function result(): CostBenchResult {
  return {
    benchmark: "glm-5.3-gateway-cost",
    startedAt: "2026-09-28T00:00:00.000Z",
    completedAt: "2026-09-28T00:01:00.000Z",
    repetitions: 1,
    budgetUsd: 10,
    spentUsd: 0.018,
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
    cases: ["exact-reasoning"],
    samples: [sample("openrouter"), sample("concentrate")],
  };
}

describe("cost benchmark reporting", () => {
  it("summarizes cost, quality, latency, routes, and fees", () => {
    const summary = summarizeCostBench(result());
    expect(summary.gateways.openrouter).toMatchObject({
      passed: 1,
      providerCostUsd: 0.01,
      costPerPassedSampleUsd: 0.01,
      medianTimeToFirstTokenMs: 200,
      routes: { "Z.ai": 1 },
    });
    expect(summary.gateways.concentrate).toMatchObject({
      passed: 1,
      providerCostUsd: 0.008,
      medianTotalLatencyMs: 800,
    });
    expect(summary.providerCostDeltaPercent).toBeCloseTo(-20);
    expect(summary.fundingFeeScenarios[1]).toMatchObject({
      creditPurchaseUsd: 100,
      feeUsd: 5.5,
    });
  });

  it("renders an auditable Markdown comparison", () => {
    const markdown = generateCostBenchMarkdown(result());
    expect(markdown).toContain("# GLM 5.3 Gateway Cost Benchmark");
    expect(markdown).toContain("| Provider-billed inference |");
    expect(markdown).toContain("| openrouter | Z.ai | 1 |");
    expect(markdown).toContain("5.5% credit-purchase fee");
  });
});
