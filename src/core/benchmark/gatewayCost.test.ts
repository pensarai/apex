import { describe, expect, it } from "vitest";
import {
  CostBudget,
  CostBudgetExceededError,
  calculateOpenRouterFundingFee,
  extractGatewayStepCost,
  MissingGatewayCostError,
  parseOpenRouterReferenceRates,
  type ReferenceTokenRates,
} from "./gatewayCost";

const rates: ReferenceTokenRates = {
  inputPerMillion: 1.4,
  outputPerMillion: 4.4,
  cacheReadPerMillion: 0.26,
  cacheWritePerMillion: 0,
  capturedAt: "2026-09-28T00:00:00.000Z",
  source: "test",
};

const usage = {
  inputTokens: 1_000_000,
  outputTokens: 100_000,
  inputTokenDetails: {
    cacheReadTokens: 200_000,
    cacheWriteTokens: 0,
  },
  outputTokenDetails: { reasoningTokens: 50_000 },
};

describe("extractGatewayStepCost", () => {
  it("normalizes OpenRouter usage, route, and billed cost", () => {
    const result = extractGatewayStepCost(
      "openrouter",
      {
        usage,
        response: { modelId: "z-ai/glm-5.3" },
        providerMetadata: {
          openrouter: {
            provider: "NovitaAI",
            usage: { cost: 1.23, isByok: false },
          },
        },
      },
      rates,
    );

    expect(result).toMatchObject({
      providerCostUsd: 1.23,
      byok: false,
      servedModel: "z-ai/glm-5.3",
      routes: ["NovitaAI"],
      inputTokens: 1_000_000,
      outputTokens: 100_000,
      reasoningTokens: 50_000,
      cacheReadTokens: 200_000,
      cacheWriteTokens: 0,
    });
    expect(result.referenceCostUsd).toBeCloseTo(1.612, 8);
  });

  it("normalizes Concentrate cost breakdown routes", () => {
    const result = extractGatewayStepCost(
      "concentrate",
      {
        usage,
        response: { modelId: "glm-5.3" },
        providerMetadata: {
          concentrate: {
            model: "fireworks/glm-5.3",
            cost: {
              total: 0.91,
              byok: false,
              breakdown: {
                "fireworks/glm-5.3": {
                  input_tokens: 1_000_000,
                  output_tokens: 100_000,
                },
              },
            },
          },
        },
      },
      rates,
    );

    expect(result).toMatchObject({
      providerCostUsd: 0.91,
      byok: false,
      servedModel: "fireworks/glm-5.3",
      routes: ["fireworks/glm-5.3"],
    });
  });

  it("fails loud when a successful step has no billed-cost metadata", () => {
    expect(() =>
      extractGatewayStepCost(
        "concentrate",
        { usage, providerMetadata: { concentrate: {} } },
        rates,
      ),
    ).toThrow(MissingGatewayCostError);
  });
});

describe("parseOpenRouterReferenceRates", () => {
  it("captures per-million GLM 5.3 list rates", () => {
    expect(
      parseOpenRouterReferenceRates(
        {
          data: [
            {
              id: "z-ai/glm-5.3",
              pricing: {
                prompt: "0.0000014",
                completion: "0.0000044",
                input_cache_read: "0.00000026",
              },
            },
          ],
        },
        "2026-09-28T12:00:00.000Z",
      ),
    ).toMatchObject({
      inputPerMillion: 1.4,
      outputPerMillion: 4.4,
      cacheReadPerMillion: 0.26,
      cacheWritePerMillion: 0,
      capturedAt: "2026-09-28T12:00:00.000Z",
    });
  });

  it("rejects a catalog without the exact model", () => {
    expect(() =>
      parseOpenRouterReferenceRates({ data: [] }, new Date().toISOString()),
    ).toThrow(/missing pricing\.prompt/);
  });
});

describe("CostBudget", () => {
  it("guards reservations and actual spend", () => {
    const budget = new CostBudget(1);
    budget.assertCanStart(0.5);
    budget.record(0.6);
    expect(budget.remainingUsd).toBeCloseTo(0.4);
    expect(() => budget.assertCanStart(0.5)).toThrow(CostBudgetExceededError);
    expect(() => budget.record(0.5)).toThrow(CostBudgetExceededError);
    expect(budget.spentUsd).toBeCloseTo(1.1);
  });
});

describe("calculateOpenRouterFundingFee", () => {
  it("applies the minimum to small purchases and percentage otherwise", () => {
    expect(calculateOpenRouterFundingFee(10)).toBe(0.8);
    expect(calculateOpenRouterFundingFee(100)).toBeCloseTo(5.5);
    expect(calculateOpenRouterFundingFee(1_000)).toBeCloseTo(55);
  });
});
