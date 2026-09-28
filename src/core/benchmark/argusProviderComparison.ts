import type { BenchmarkRunResult, BenchmarkSuiteResult } from "./types";

export type ArgusProviderComparison = {
  openrouter: BenchmarkSuiteResult;
  concentrate: BenchmarkSuiteResult;
  perRunBudgetUsd: number;
};

export type ArgusProviderSummary = {
  runs: number;
  completed: number;
  flagsCaptured: number;
  findings: number;
  providerCostUsd: number;
  referenceCostUsd: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  durationMinutes: number;
  costPerFlagUsd: number | null;
  routes: string[];
};

function usd(value: number | null): string {
  return value === null ? "—" : `$${value.toFixed(4)}`;
}

function tokenCount(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return String(value);
}

function runCost(run: BenchmarkRunResult | undefined): number | null {
  return run?.tokenMetrics?.providerCostUsd ?? null;
}

function runRoutes(run: BenchmarkRunResult | undefined): string {
  const routes = run?.tokenMetrics?.routes ?? [];
  return routes.length > 0 ? routes.join(", ") : "—";
}

export function summarizeArgusProvider(
  result: BenchmarkSuiteResult,
): ArgusProviderSummary {
  const providerCostUsd = result.results.reduce(
    (sum, run) => sum + (run.tokenMetrics?.providerCostUsd ?? 0),
    0,
  );
  const flagsCaptured = result.results.filter((run) => run.flagDetected).length;
  return {
    runs: result.results.length,
    completed: result.results.filter((run) => run.status === "success").length,
    flagsCaptured,
    findings: result.results.reduce((sum, run) => sum + run.findingsCount, 0),
    providerCostUsd,
    referenceCostUsd: result.results.reduce(
      (sum, run) => sum + (run.tokenMetrics?.referenceCostUsd ?? 0),
      0,
    ),
    inputTokens: result.summary.totalInputTokens,
    outputTokens: result.summary.totalOutputTokens,
    cacheReadTokens: result.summary.totalCacheReadTokens,
    durationMinutes: result.summary.totalDurationMinutes,
    costPerFlagUsd: flagsCaptured > 0 ? providerCostUsd / flagsCaptured : null,
    routes: [
      ...new Set(
        result.results.flatMap((run) => run.tokenMetrics?.routes ?? []),
      ),
    ].sort(),
  };
}

function percentDelta(concentrate: number, openrouter: number): number | null {
  return openrouter > 0
    ? ((concentrate - openrouter) / openrouter) * 100
    : null;
}

function deltaText(value: number | null): string {
  if (value === null) return "unavailable";
  return `${value >= 0 ? "+" : ""}${value.toFixed(1)}%`;
}

function branchRows(comparison: ArgusProviderComparison): string[] {
  const openrouter = new Map(
    comparison.openrouter.results.map((run) => [run.branch, run]),
  );
  const concentrate = new Map(
    comparison.concentrate.results.map((run) => [run.branch, run]),
  );
  const branches = [...new Set([...openrouter.keys(), ...concentrate.keys()])];

  return branches.sort().map((branch) => {
    const openrouterRun = openrouter.get(branch);
    const concentrateRun = concentrate.get(branch);
    return [
      `| ${branch}`,
      openrouterRun?.status ?? "missing",
      openrouterRun?.flagDetected ? "yes" : "no",
      String(openrouterRun?.findingsCount ?? 0),
      usd(runCost(openrouterRun)),
      `${((openrouterRun?.duration ?? 0) / 60_000).toFixed(1)}m`,
      runRoutes(openrouterRun),
      concentrateRun?.status ?? "missing",
      concentrateRun?.flagDetected ? "yes" : "no",
      String(concentrateRun?.findingsCount ?? 0),
      usd(runCost(concentrateRun)),
      `${((concentrateRun?.duration ?? 0) / 60_000).toFixed(1)}m`,
      `${runRoutes(concentrateRun)} |`,
    ].join(" | ");
  });
}

export function generateArgusProviderComparisonMarkdown(
  comparison: ArgusProviderComparison,
): string {
  const openrouter = summarizeArgusProvider(comparison.openrouter);
  const concentrate = summarizeArgusProvider(comparison.concentrate);
  const totalSpend = openrouter.providerCostUsd + concentrate.providerCostUsd;
  const maximumSpend =
    comparison.perRunBudgetUsd * (openrouter.runs + concentrate.runs);
  const bothFastStrike =
    comparison.openrouter.fastStrike === true &&
    comparison.concentrate.fastStrike === true;

  return [
    "# GLM 5.3 Argus Provider Comparison",
    "",
    `Mode: ${bothFastStrike ? "Fast Strike" : "mixed or unspecified"}`,
    `Models: \`${comparison.openrouter.model}\` vs \`${comparison.concentrate.model}\``,
    "",
    "## Overall",
    "",
    "| Metric | OpenRouter | Concentrate |",
    "| --- | ---: | ---: |",
    `| Completed | ${openrouter.completed}/${openrouter.runs} | ${concentrate.completed}/${concentrate.runs} |`,
    `| Flags captured | ${openrouter.flagsCaptured}/${openrouter.runs} | ${concentrate.flagsCaptured}/${concentrate.runs} |`,
    `| Findings | ${openrouter.findings} | ${concentrate.findings} |`,
    `| Provider-billed cost | ${usd(openrouter.providerCostUsd)} | ${usd(concentrate.providerCostUsd)} |`,
    `| Reference-rate cost | ${usd(openrouter.referenceCostUsd)} | ${usd(concentrate.referenceCostUsd)} |`,
    `| Cost per captured flag | ${usd(openrouter.costPerFlagUsd)} | ${usd(concentrate.costPerFlagUsd)} |`,
    `| Input tokens | ${tokenCount(openrouter.inputTokens)} | ${tokenCount(concentrate.inputTokens)} |`,
    `| Output tokens | ${tokenCount(openrouter.outputTokens)} | ${tokenCount(concentrate.outputTokens)} |`,
    `| Cache read tokens | ${tokenCount(openrouter.cacheReadTokens)} | ${tokenCount(concentrate.cacheReadTokens)} |`,
    `| Duration | ${openrouter.durationMinutes.toFixed(1)}m | ${concentrate.durationMinutes.toFixed(1)}m |`,
    `| Routes | ${openrouter.routes.join(", ") || "—"} | ${concentrate.routes.join(", ") || "—"} |`,
    "",
    `Concentrate billed-cost delta vs OpenRouter: ${deltaText(percentDelta(concentrate.providerCostUsd, openrouter.providerCostUsd))}.`,
    `Concentrate duration delta vs OpenRouter: ${deltaText(percentDelta(concentrate.durationMinutes, openrouter.durationMinutes))}.`,
    "",
    "## Per benchmark",
    "",
    "| Benchmark | OR status | OR flag | OR findings | OR cost | OR time | OR routes | CN status | CN flag | CN findings | CN cost | CN time | CN routes |",
    "| --- | --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: | ---: | ---: | --- |",
    ...branchRows(comparison),
    "",
    "## Spend guard",
    "",
    `Measured provider spend: ${usd(totalSpend)}.`,
    `Maximum configured spend: ${usd(maximumSpend)} (${openrouter.runs + concentrate.runs} runs × ${usd(comparison.perRunBudgetUsd)}).`,
    totalSpend <= maximumSpend
      ? "The measured spend remained within the configured ceiling."
      : "WARNING: measured spend exceeded the configured ceiling.",
    "",
    "The separate LLM comparison scorer was disabled. Flag capture is the deterministic outcome metric; findings count is shown as supporting context.",
    "",
  ].join("\n");
}

export function generateArgusProviderComparisonJson(
  comparison: ArgusProviderComparison,
): string {
  return JSON.stringify(
    {
      comparison,
      summaries: {
        openrouter: summarizeArgusProvider(comparison.openrouter),
        concentrate: summarizeArgusProvider(comparison.concentrate),
      },
    },
    null,
    2,
  );
}
