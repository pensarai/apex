import { describe, it, expect } from "vitest";
import type {
  UsagePeriod,
  UsageDataPoint,
  UsageSummary,
  CiUsageResponse,
} from "./ci-usage";

describe("CI Usage types", () => {
  it("UsagePeriod accepts valid values", () => {
    const periods: UsagePeriod[] = ["week", "month", "year"];
    expect(periods).toHaveLength(3);
  });

  it("UsageDataPoint has correct shape", () => {
    const point: UsageDataPoint = {
      date: "2026-03-10",
      requests: 150,
      inputTokens: 50000,
      outputTokens: 30000,
      totalTokens: 80000,
      cost: 1.25,
    };
    expect(point.date).toBe("2026-03-10");
    expect(point.totalTokens).toBe(point.inputTokens + point.outputTokens);
  });

  it("UsageSummary has correct shape", () => {
    const summary: UsageSummary = {
      totalRequests: 1000,
      totalInputTokens: 500000,
      totalOutputTokens: 300000,
      totalTokens: 800000,
      totalCost: 12.5,
      averageDailyRequests: 142.86,
      averageDailyCost: 1.79,
    };
    expect(summary.totalTokens).toBe(
      summary.totalInputTokens + summary.totalOutputTokens,
    );
  });

  it("CiUsageResponse composes correctly", () => {
    const response: CiUsageResponse = {
      period: "week",
      model: null,
      data: [
        {
          date: "2026-03-10",
          requests: 100,
          inputTokens: 40000,
          outputTokens: 20000,
          totalTokens: 60000,
          cost: 0.95,
        },
        {
          date: "2026-03-11",
          requests: 120,
          inputTokens: 45000,
          outputTokens: 25000,
          totalTokens: 70000,
          cost: 1.1,
        },
      ],
      summary: {
        totalRequests: 220,
        totalInputTokens: 85000,
        totalOutputTokens: 45000,
        totalTokens: 130000,
        totalCost: 2.05,
        averageDailyRequests: 110,
        averageDailyCost: 1.025,
      },
      models: ["claude-sonnet-4-20250514", "gpt-4o"],
    };
    expect(response.period).toBe("week");
    expect(response.data).toHaveLength(2);
    expect(response.models).toHaveLength(2);
  });

  it("CiUsageResponse with model filter", () => {
    const response: CiUsageResponse = {
      period: "month",
      model: "claude-sonnet-4-20250514",
      data: [],
      summary: {
        totalRequests: 0,
        totalInputTokens: 0,
        totalOutputTokens: 0,
        totalTokens: 0,
        totalCost: 0,
        averageDailyRequests: 0,
        averageDailyCost: 0,
      },
      models: ["claude-sonnet-4-20250514"],
    };
    expect(response.model).toBe("claude-sonnet-4-20250514");
    expect(response.data).toHaveLength(0);
  });
});
