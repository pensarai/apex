import type { BenchmarkRunResult, BenchmarkSuiteResult } from "./types";

// ---------------------------------------------------------------------------
// Text report
// ---------------------------------------------------------------------------

export function generateTextReport(result: BenchmarkSuiteResult): string {
  const { summary, results, model, repoUrl } = result;
  const lines: string[] = [];

  lines.push("═".repeat(55));
  lines.push("        ARGUS BENCHMARK SUITE RESULTS");
  lines.push("═".repeat(55));
  lines.push(
    `Model: ${model}  |  Duration: ${summary.totalDurationMinutes.toFixed(1)}m`,
  );
  lines.push("");

  // Summary
  lines.push("SUMMARY");
  lines.push("─".repeat(30));
  lines.push(
    `Total: ${summary.total}  |  Passed: ${summary.passed}  |  Failed: ${summary.failed}  |  Timeout: ${summary.timedOut}`,
  );
  lines.push("");

  const barWidth = 35;

  // Flag capture bar
  const flagFilled = Math.round(summary.flagCaptureRate * barWidth);
  lines.push(
    `Flag Capture:  [${"█".repeat(flagFilled)}${"░".repeat(barWidth - flagFilled)}] ${(summary.flagCaptureRate * 100).toFixed(1)}%`,
  );

  // Vuln detection bar
  const vulnFilled = Math.round(summary.vulnDetectionRate * barWidth);
  lines.push(
    `Vuln Found:    [${"█".repeat(vulnFilled)}${"░".repeat(barWidth - vulnFilled)}] ${(summary.vulnDetectionRate * 100).toFixed(1)}%`,
  );

  lines.push(
    `Avg Precision: ${(summary.avgPrecision * 100).toFixed(1)}%  |  Avg Recall: ${(summary.avgRecall * 100).toFixed(1)}%`,
  );
  lines.push("");

  // Per-benchmark results table
  lines.push("PER-BENCHMARK RESULTS");
  lines.push("─".repeat(30));

  const header =
    padRight("Branch", 16) +
    padRight("Diff", 6) +
    padRight("Status", 9) +
    padRight("Flag", 6) +
    padRight("Vulns", 7) +
    padRight("Precision", 11) +
    padRight("Recall", 9) +
    "Duration";
  lines.push(header);

  for (const r of results) {
    const diff = r.metadata?.difficulty?.toString() ?? "-";
    const status = r.status === "success" ? "PASS" : r.status.toUpperCase();
    const flag = r.flagDetected ? "Y" : "N";
    const vulns = r.findingsCount.toString();
    const precision = r.comparisonResult
      ? `${(r.comparisonResult.precision * 100).toFixed(0)}%`
      : "-";
    const recall = r.comparisonResult
      ? `${(r.comparisonResult.recall * 100).toFixed(0)}%`
      : "-";
    const duration = `${(r.duration / 60000).toFixed(1)}m`;

    lines.push(
      padRight(r.branch, 16) +
        padRight(diff, 6) +
        padRight(status, 9) +
        padRight(flag, 6) +
        padRight(vulns, 7) +
        padRight(precision, 11) +
        padRight(recall, 9) +
        duration,
    );
  }

  lines.push("");

  // By difficulty
  const difficultyGroups = groupBy(
    results.filter((r) => r.metadata),
    (r) => r.metadata!.difficulty,
  );

  if (Object.keys(difficultyGroups).length > 0) {
    lines.push("BY DIFFICULTY");
    lines.push("─".repeat(30));

    const difficultyLabels: Record<number, string> = {
      1: "Easy",
      2: "Medium",
      3: "Hard",
    };

    for (const [diff, group] of Object.entries(difficultyGroups).sort(
      (a, b) => Number(a[0]) - Number(b[0]),
    )) {
      const flagCount = group.filter((r) => r.flagDetected).length;
      const label = difficultyLabels[Number(diff)] || `Level ${diff}`;
      const pct =
        group.length > 0
          ? ((flagCount / group.length) * 100).toFixed(1)
          : "0.0";
      lines.push(
        `${padRight(`${label} (${diff}):`, 14)}${flagCount}/${group.length} flags   (${pct}%)`,
      );
    }
    lines.push("");
  }

  // By category (tags)
  const tagMap = new Map<string, BenchmarkRunResult[]>();
  for (const r of results) {
    if (r.metadata?.tags) {
      for (const tag of r.metadata.tags) {
        if (!tagMap.has(tag)) tagMap.set(tag, []);
        tagMap.get(tag)!.push(r);
      }
    }
  }

  if (tagMap.size > 0) {
    lines.push("BY CATEGORY");
    lines.push("─".repeat(30));

    for (const [tag, group] of [...tagMap.entries()].sort((a, b) =>
      a[0].localeCompare(b[0]),
    )) {
      const flagCount = group.filter((r) => r.flagDetected).length;
      const pct =
        group.length > 0
          ? ((flagCount / group.length) * 100).toFixed(1)
          : "0.0";
      lines.push(
        `${padRight(`${tag}:`, 16)}${flagCount}/${group.length}  (${pct}%)`,
      );
    }
    lines.push("");
  }

  // Token usage & caching
  if (summary.totalInputTokens > 0) {
    lines.push("TOKEN USAGE & CACHING");
    lines.push("─".repeat(30));
    lines.push(
      `Total Tokens:  ${formatTokenCount(summary.totalInputTokens)} input  |  ${formatTokenCount(summary.totalOutputTokens)} output`,
    );
    lines.push(
      `Cache Read:    ${formatTokenCount(summary.totalCacheReadTokens)} (${(summary.cacheHitRate * 100).toFixed(1)}% hit rate)`,
    );
    lines.push(
      `Cache Write:   ${formatTokenCount(summary.totalCacheWriteTokens)}`,
    );
    lines.push("");

    const savings =
      summary.totalEstimatedCostWithoutCacheUsd - summary.totalEstimatedCostUsd;
    const savingsPct =
      summary.totalEstimatedCostWithoutCacheUsd > 0
        ? (savings / summary.totalEstimatedCostWithoutCacheUsd) * 100
        : 0;

    lines.push(
      `Estimated Cost:        $${summary.totalEstimatedCostUsd.toFixed(2)}`,
    );
    lines.push(
      `Cost Without Caching:  $${summary.totalEstimatedCostWithoutCacheUsd.toFixed(2)}`,
    );
    lines.push(
      `Savings:               $${savings.toFixed(2)} (${savingsPct.toFixed(1)}%)`,
    );
    lines.push("");

    // Per-benchmark token table
    const tokenResults = results.filter((r) => r.tokenMetrics);
    if (tokenResults.length > 0) {
      lines.push("PER-BENCHMARK TOKEN USAGE");
      lines.push("─".repeat(30));
      lines.push(
        padRight("Branch", 16) +
          padRight("Input", 10) +
          padRight("Cache Rd", 10) +
          padRight("Hit%", 8) +
          "Cost",
      );

      for (const r of tokenResults) {
        const t = r.tokenMetrics!;
        const hitRate =
          t.cacheReadTokens + t.noCacheInputTokens > 0
            ? (
                (t.cacheReadTokens /
                  (t.cacheReadTokens + t.noCacheInputTokens)) *
                100
              ).toFixed(1) + "%"
            : "-";

        lines.push(
          padRight(r.branch, 16) +
            padRight(formatTokenCount(t.inputTokens), 10) +
            padRight(formatTokenCount(t.cacheReadTokens), 10) +
            padRight(hitRate, 8) +
            `$${t.estimatedCostUsd.toFixed(2)}`,
        );
      }
      lines.push("");
    }
  }

  lines.push("═".repeat(55));

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// JSON report
// ---------------------------------------------------------------------------

export function generateJsonReport(result: BenchmarkSuiteResult): string {
  return JSON.stringify(result, null, 2);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTokenCount(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(0)}K`;
  return n.toString();
}

function padRight(s: string, width: number): string {
  return s.length >= width ? s : s + " ".repeat(width - s.length);
}

function groupBy<T>(
  items: T[],
  key: (item: T) => string | number,
): Record<string, T[]> {
  const groups: Record<string, T[]> = {};
  for (const item of items) {
    const k = String(key(item));
    if (!groups[k]) groups[k] = [];
    groups[k]!.push(item);
  }
  return groups;
}
