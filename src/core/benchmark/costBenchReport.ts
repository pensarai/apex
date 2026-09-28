import type { CostBenchResult, CostBenchSample } from "./costBench";
import {
  type CostBenchGateway,
  calculateOpenRouterFundingFee,
} from "./gatewayCost";

export type GatewayCostBenchSummary = {
  gateway: CostBenchGateway;
  samples: number;
  passed: number;
  failed: number;
  errors: number;
  passRate: number;
  providerCostUsd: number;
  referenceCostUsd: number;
  costPerPassedSampleUsd: number | null;
  inputTokens: number;
  outputTokens: number;
  reasoningTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  cacheHitRate: number;
  medianTimeToFirstTokenMs: number | null;
  medianTotalLatencyMs: number | null;
  medianOutputTokensPerSecond: number | null;
  routes: Record<string, number>;
};

export type CostBenchSummary = {
  gateways: Record<CostBenchGateway, GatewayCostBenchSummary>;
  providerCostDeltaPercent: number | null;
  referenceCostDeltaPercent: number | null;
  fundingFeeScenarios: Array<{
    creditPurchaseUsd: number;
    feeUsd: number;
    effectiveFeePercent: number;
    benchmarkCashAdjustedCostUsd: number;
  }>;
};

function sum(samples: CostBenchSample[], field: keyof CostBenchSample): number {
  return samples.reduce((total, sample) => {
    const value = sample[field];
    return total + (typeof value === "number" ? value : 0);
  }, 0);
}

function median(values: Array<number | null>): number | null {
  const sorted = values
    .filter(
      (value): value is number => value !== null && Number.isFinite(value),
    )
    .sort((a, b) => a - b);
  if (sorted.length === 0) return null;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2
    : (sorted[middle] ?? null);
}

function summarizeGateway(
  gateway: CostBenchGateway,
  samples: CostBenchSample[],
): GatewayCostBenchSummary {
  const selected = samples.filter((sample) => sample.gateway === gateway);
  const passed = selected.filter((sample) => sample.status === "passed").length;
  const failed = selected.filter((sample) => sample.status === "failed").length;
  const errors = selected.filter((sample) => sample.status === "error").length;
  const providerCostUsd = sum(selected, "providerCostUsd");
  const cacheReadTokens = sum(selected, "cacheReadTokens");
  const inputTokens = sum(selected, "inputTokens");
  const cacheWriteTokens = sum(selected, "cacheWriteTokens");
  const uncachedInputTokens = Math.max(
    0,
    inputTokens - cacheReadTokens - cacheWriteTokens,
  );
  const routes: Record<string, number> = {};
  for (const route of selected.flatMap((sample) => sample.routes)) {
    routes[route] = (routes[route] ?? 0) + 1;
  }

  return {
    gateway,
    samples: selected.length,
    passed,
    failed,
    errors,
    passRate: selected.length > 0 ? passed / selected.length : 0,
    providerCostUsd,
    referenceCostUsd: sum(selected, "referenceCostUsd"),
    costPerPassedSampleUsd: passed > 0 ? providerCostUsd / passed : null,
    inputTokens,
    outputTokens: sum(selected, "outputTokens"),
    reasoningTokens: sum(selected, "reasoningTokens"),
    cacheReadTokens,
    cacheWriteTokens,
    cacheHitRate:
      cacheReadTokens + uncachedInputTokens > 0
        ? cacheReadTokens / (cacheReadTokens + uncachedInputTokens)
        : 0,
    medianTimeToFirstTokenMs: median(
      selected.map((sample) => sample.timeToFirstTokenMs),
    ),
    medianTotalLatencyMs: median(
      selected.map((sample) => sample.totalLatencyMs),
    ),
    medianOutputTokensPerSecond: median(
      selected.map((sample) => sample.outputTokensPerSecond),
    ),
    routes,
  };
}

function percentDelta(concentrate: number, openrouter: number): number | null {
  return openrouter > 0
    ? ((concentrate - openrouter) / openrouter) * 100
    : null;
}

export function summarizeCostBench(result: CostBenchResult): CostBenchSummary {
  const openrouter = summarizeGateway("openrouter", result.samples);
  const concentrate = summarizeGateway("concentrate", result.samples);
  const fundingFeeScenarios = [10, 100, 1_000].map((creditPurchaseUsd) => {
    const feeUsd = calculateOpenRouterFundingFee(creditPurchaseUsd);
    const effectiveFeePercent = (feeUsd / creditPurchaseUsd) * 100;
    return {
      creditPurchaseUsd,
      feeUsd,
      effectiveFeePercent,
      benchmarkCashAdjustedCostUsd:
        openrouter.providerCostUsd * (1 + feeUsd / creditPurchaseUsd),
    };
  });

  return {
    gateways: { openrouter, concentrate },
    providerCostDeltaPercent: percentDelta(
      concentrate.providerCostUsd,
      openrouter.providerCostUsd,
    ),
    referenceCostDeltaPercent: percentDelta(
      concentrate.referenceCostUsd,
      openrouter.referenceCostUsd,
    ),
    fundingFeeScenarios,
  };
}

function usd(value: number | null): string {
  return value === null ? "—" : `$${value.toFixed(6)}`;
}

function number(value: number | null, digits = 1): string {
  return value === null ? "—" : value.toFixed(digits);
}

function percent(value: number | null): string {
  if (value === null) return "—";
  return `${value >= 0 ? "+" : ""}${value.toFixed(1)}%`;
}

function tokenCount(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return String(value);
}

function caseRows(result: CostBenchResult): string[] {
  const rows: string[] = [];
  for (const caseId of result.cases) {
    for (const gateway of ["openrouter", "concentrate"] as const) {
      const samples = result.samples.filter(
        (sample) => sample.caseId === caseId && sample.gateway === gateway,
      );
      const passed = samples.filter(
        (sample) => sample.status === "passed",
      ).length;
      rows.push(
        `| ${caseId} | ${gateway} | ${passed}/${samples.length} | ${usd(sum(samples, "providerCostUsd"))} | ${number(median(samples.map((sample) => sample.timeToFirstTokenMs)), 0)} | ${number(median(samples.map((sample) => sample.totalLatencyMs)), 0)} |`,
      );
    }
  }
  return rows;
}

function routeRows(summary: CostBenchSummary): string[] {
  const rows: string[] = [];
  for (const gateway of ["openrouter", "concentrate"] as const) {
    const routes = Object.entries(summary.gateways[gateway].routes);
    if (routes.length === 0) {
      rows.push(`| ${gateway} | unavailable | 0 |`);
      continue;
    }
    for (const [route, count] of routes.sort(([a], [b]) =>
      a.localeCompare(b),
    )) {
      rows.push(`| ${gateway} | ${route} | ${count} |`);
    }
  }
  return rows;
}

export function generateCostBenchMarkdown(result: CostBenchResult): string {
  const summary = summarizeCostBench(result);
  const openrouter = summary.gateways.openrouter;
  const concentrate = summary.gateways.concentrate;
  const rates = result.referenceRates;

  return [
    "# GLM 5.3 Gateway Cost Benchmark",
    "",
    `Run: ${result.startedAt} to ${result.completedAt}`,
    "",
    "## Method",
    "",
    `- Exact models: OpenRouter \`${result.models.openrouter}\`; Concentrate \`${result.models.concentrate}\`.`,
    "- Routing: each gateway's default provider routing; selected routes are reported below.",
    `- Workload: ${result.cases.length} deterministic cases × ${result.repetitions} repetitions × 2 gateways, interleaved.`,
    `- Spend guard: $${result.budgetUsd.toFixed(2)}; provider-reported spend was ${usd(result.spentUsd)}.`,
    "- Quality gate: deterministic output/tool validation. Cost per pass is reported so invalid output cannot look artificially cheap.",
    "",
    "## Reference pricing snapshot",
    "",
    `Captured ${rates.capturedAt} from ${rates.source}. These rates normalize token efficiency; provider-reported charges remain the source of truth for billed spend.`,
    "",
    "| Input / 1M | Output / 1M | Cache read / 1M | Cache write / 1M |",
    "| ---: | ---: | ---: | ---: |",
    `| $${rates.inputPerMillion.toFixed(4)} | $${rates.outputPerMillion.toFixed(4)} | $${rates.cacheReadPerMillion.toFixed(4)} | $${rates.cacheWritePerMillion.toFixed(4)} |`,
    "",
    "## Head-to-head",
    "",
    "| Metric | OpenRouter | Concentrate |",
    "| --- | ---: | ---: |",
    `| Passed | ${openrouter.passed}/${openrouter.samples} | ${concentrate.passed}/${concentrate.samples} |`,
    `| Errors | ${openrouter.errors} | ${concentrate.errors} |`,
    `| Provider-billed inference | ${usd(openrouter.providerCostUsd)} | ${usd(concentrate.providerCostUsd)} |`,
    `| Reference-rate cost | ${usd(openrouter.referenceCostUsd)} | ${usd(concentrate.referenceCostUsd)} |`,
    `| Cost / passing sample | ${usd(openrouter.costPerPassedSampleUsd)} | ${usd(concentrate.costPerPassedSampleUsd)} |`,
    `| Input tokens | ${tokenCount(openrouter.inputTokens)} | ${tokenCount(concentrate.inputTokens)} |`,
    `| Output tokens | ${tokenCount(openrouter.outputTokens)} | ${tokenCount(concentrate.outputTokens)} |`,
    `| Reasoning tokens | ${tokenCount(openrouter.reasoningTokens)} | ${tokenCount(concentrate.reasoningTokens)} |`,
    `| Cache read | ${tokenCount(openrouter.cacheReadTokens)} | ${tokenCount(concentrate.cacheReadTokens)} |`,
    `| Cache hit rate | ${(openrouter.cacheHitRate * 100).toFixed(1)}% | ${(concentrate.cacheHitRate * 100).toFixed(1)}% |`,
    `| Median TTFT | ${number(openrouter.medianTimeToFirstTokenMs, 0)} ms | ${number(concentrate.medianTimeToFirstTokenMs, 0)} ms |`,
    `| Median total latency | ${number(openrouter.medianTotalLatencyMs, 0)} ms | ${number(concentrate.medianTotalLatencyMs, 0)} ms |`,
    `| Median output throughput | ${number(openrouter.medianOutputTokensPerSecond)} tok/s | ${number(concentrate.medianOutputTokensPerSecond)} tok/s |`,
    "",
    `Concentrate provider-billed cost delta vs OpenRouter: ${percent(summary.providerCostDeltaPercent)}.`,
    `Concentrate normalized token-cost delta vs OpenRouter: ${percent(summary.referenceCostDeltaPercent)}.`,
    "",
    "## Per-case results",
    "",
    "| Case | Gateway | Passed | Billed cost | Median TTFT ms | Median latency ms |",
    "| --- | --- | ---: | ---: | ---: | ---: |",
    ...caseRows(result),
    "",
    "## Route distribution",
    "",
    "| Gateway | Served route | Samples / steps observed |",
    "| --- | --- | ---: |",
    ...routeRows(summary),
    "",
    "## Gateway fee sensitivity",
    "",
    "Concentrate publishes zero platform and card fees. OpenRouter publishes a 5.5% credit-purchase fee with a $0.80 minimum. That fee is not part of per-request `usage.cost`, so cash-adjusted benchmark cost depends on credit purchase size.",
    "",
    "| OpenRouter credit purchase | Funding fee | Effective fee | Cash-adjusted benchmark cost |",
    "| ---: | ---: | ---: | ---: |",
    ...summary.fundingFeeScenarios.map(
      (scenario) =>
        `| $${scenario.creditPurchaseUsd.toFixed(0)} | ${usd(scenario.feeUsd)} | ${scenario.effectiveFeePercent.toFixed(2)}% | ${usd(scenario.benchmarkCashAdjustedCostUsd)} |`,
    ),
    "",
    "Sources: [OpenRouter pricing](https://openrouter.ai/pricing), [OpenRouter usage accounting](https://openrouter.ai/docs/cookbook/administration/usage-accounting), [Concentrate pricing](https://concentrate.ai/pricing), [Concentrate GLM 5.3 catalog](https://concentrate.ai/models/glm-5.3).",
    "",
    "## Limitations",
    "",
    "- Default routing intentionally allows different upstream hosts and quantizations. Route mix can change over time.",
    "- Results are a bounded pilot, not a model-quality leaderboard. Re-run before a purchasing decision.",
    "- Reasoning tokens are included in output billing; the separate reasoning count depends on each upstream's telemetry.",
    "- Cache behavior depends on route affinity and warm state, so cold/warm cases should be read together.",
    ...(result.stoppedReason
      ? ["", `The run stopped early: ${result.stoppedReason}`]
      : []),
    "",
  ].join("\n");
}

export function generateCostBenchJson(result: CostBenchResult): string {
  return JSON.stringify(
    { result, summary: summarizeCostBench(result) },
    null,
    2,
  );
}
