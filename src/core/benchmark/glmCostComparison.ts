import type { CostBenchResult } from "./costBench";
import {
  generateCostBenchMarkdown,
  summarizeCostBench,
} from "./costBenchReport";
import type { BenchmarkSuiteResult } from "./types";

export type GlmGatewayCostComparison = {
  micro: CostBenchResult;
  argus: {
    branch: string;
    openrouter: BenchmarkSuiteResult;
    concentrate: BenchmarkSuiteResult;
  };
  budgetUsd: number;
};

function argusCost(result: BenchmarkSuiteResult): number {
  return result.summary.totalProviderCostUsd ?? 0;
}

function usd(value: number | null): string {
  return value === null ? "—" : `$${value.toFixed(6)}`;
}

function tokens(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return String(value);
}

function routes(result: BenchmarkSuiteResult): string {
  const values = [
    ...new Set(result.results.flatMap((run) => run.tokenMetrics?.routes ?? [])),
  ];
  return values.length > 0 ? values.sort().join(", ") : "unavailable";
}

export function totalComparisonSpend(
  comparison: GlmGatewayCostComparison,
): number {
  return (
    comparison.micro.spentUsd +
    argusCost(comparison.argus.openrouter) +
    argusCost(comparison.argus.concentrate)
  );
}

export function generateGlmGatewayComparisonMarkdown(
  comparison: GlmGatewayCostComparison,
): string {
  const base = generateCostBenchMarkdown(comparison.micro).trimEnd();
  const openrouter = comparison.argus.openrouter;
  const concentrate = comparison.argus.concentrate;
  const openrouterRun = openrouter.results[0];
  const concentrateRun = concentrate.results[0];
  const spend = totalComparisonSpend(comparison);
  const microSummary = summarizeCostBench(comparison.micro);
  const providerDelta =
    openrouter.summary.totalProviderCostUsd &&
    concentrate.summary.totalProviderCostUsd !== null
      ? ((concentrate.summary.totalProviderCostUsd -
          openrouter.summary.totalProviderCostUsd) /
          openrouter.summary.totalProviderCostUsd) *
        100
      : null;

  return [
    base,
    "",
    "## Argus production-shaped pilot",
    "",
    `Both gateways ran local Argus \`${comparison.argus.branch}\` once with the separate LLM comparison scorer disabled. Flag capture is the deterministic quality gate; one target is not enough for a general model-quality conclusion.`,
    "",
    "| Metric | OpenRouter | Concentrate |",
    "| --- | ---: | ---: |",
    `| Run status | ${openrouterRun?.status ?? "missing"} | ${concentrateRun?.status ?? "missing"} |`,
    `| Flag captured | ${openrouterRun?.flagDetected ? "yes" : "no"} | ${concentrateRun?.flagDetected ? "yes" : "no"} |`,
    `| Findings | ${openrouterRun?.findingsCount ?? 0} | ${concentrateRun?.findingsCount ?? 0} |`,
    `| Provider-billed inference | ${usd(openrouter.summary.totalProviderCostUsd)} | ${usd(concentrate.summary.totalProviderCostUsd)} |`,
    `| Reference-rate cost | ${usd(openrouter.summary.totalReferenceCostUsd)} | ${usd(concentrate.summary.totalReferenceCostUsd)} |`,
    `| Input tokens | ${tokens(openrouter.summary.totalInputTokens)} | ${tokens(concentrate.summary.totalInputTokens)} |`,
    `| Output tokens | ${tokens(openrouter.summary.totalOutputTokens)} | ${tokens(concentrate.summary.totalOutputTokens)} |`,
    `| Cache read | ${tokens(openrouter.summary.totalCacheReadTokens)} | ${tokens(concentrate.summary.totalCacheReadTokens)} |`,
    `| Duration | ${openrouter.summary.totalDurationMinutes.toFixed(1)} min | ${concentrate.summary.totalDurationMinutes.toFixed(1)} min |`,
    `| Routes | ${routes(openrouter)} | ${routes(concentrate)} |`,
    "",
    providerDelta === null
      ? "The Argus billed-cost delta is unavailable because one run did not return tracked cost."
      : `Concentrate Argus billed-cost delta vs OpenRouter: ${providerDelta >= 0 ? "+" : ""}${providerDelta.toFixed(1)}%.`,
    "",
    "## Combined spend guard",
    "",
    `- Microbenchmark: ${usd(comparison.micro.spentUsd)}`,
    `- OpenRouter Argus: ${usd(openrouter.summary.totalProviderCostUsd)}`,
    `- Concentrate Argus: ${usd(concentrate.summary.totalProviderCostUsd)}`,
    `- Combined: ${usd(spend)} / $${comparison.budgetUsd.toFixed(2)}`,
    `- Micro pass rates: OpenRouter ${(microSummary.gateways.openrouter.passRate * 100).toFixed(1)}%; Concentrate ${(microSummary.gateways.concentrate.passRate * 100).toFixed(1)}%`,
    "",
    spend <= comparison.budgetUsd
      ? "The measured provider spend remained within the approved ceiling."
      : "WARNING: measured provider spend exceeded the approved ceiling.",
    "",
  ].join("\n");
}

export function generateGlmGatewayComparisonJson(
  comparison: GlmGatewayCostComparison,
): string {
  return JSON.stringify(
    {
      comparison,
      microSummary: summarizeCostBench(comparison.micro),
      combinedProviderSpendUsd: totalComparisonSpend(comparison),
    },
    null,
    2,
  );
}
