/**
 * Threat Model Benchmark — Reporter
 *
 * Generates summary JSON and text reports.
 */

import type { SuiteResult } from "./types";

export function generateTextReport(result: SuiteResult): string {
  const lines: string[] = [];
  const hr = "=".repeat(70);

  lines.push(hr);
  lines.push(`THREAT MODEL BENCHMARK RESULTS`);
  lines.push(hr);
  lines.push(`Run ID:    ${result.runId}`);
  lines.push(`Model:     ${result.model}`);
  lines.push(`Timestamp: ${result.timestamp}`);
  lines.push(`Apps:      ${result.config.apps.length}`);
  lines.push(`Fast mode: ${result.config.fast}`);
  lines.push("");

  // Headline metrics
  lines.push(`HEADLINE METRICS`);
  lines.push("-".repeat(40));
  lines.push(
    `  Overall Score:       ${result.headline.overallScore.toFixed(1)}/100`,
  );
  lines.push(
    `  Vulnerability Recall: ${(result.headline.vulnerabilityRecall * 100).toFixed(1)}%`,
  );
  lines.push(
    `  False Positive Rate:  ${(result.headline.falsePositiveRate * 100).toFixed(1)}%`,
  );
  lines.push(
    `  Grounding Score:     ${(result.headline.groundingScore * 100).toFixed(1)}%`,
  );
  lines.push(
    `  Total Cost:          $${result.headline.totalCostUsd.toFixed(2)}`,
  );
  lines.push("");

  // Per-app table
  lines.push(`PER-APP RESULTS`);
  lines.push("-".repeat(70));

  const header = [
    "App".padEnd(14),
    "Status".padEnd(10),
    "Overall".padEnd(9),
    "Struct".padEnd(8),
    "Ground".padEnd(8),
    "AntiPat".padEnd(8),
    "Steps".padEnd(7),
  ].join(" ");
  lines.push(`  ${header}`);
  lines.push(`  ${"-".repeat(64)}`);

  for (const [appId, s] of Object.entries(result.perApp)) {
    const row = [
      appId.padEnd(14),
      s.status.padEnd(10),
      `${s.overall.toFixed(1)}`.padStart(6).padEnd(9),
      `${((s.structural?.score ?? 0) * 100).toFixed(0)}%`.padStart(5).padEnd(8),
      `${((s.grounding?.score ?? 0) * 100).toFixed(0)}%`.padStart(5).padEnd(8),
      `${((s.antipattern?.score ?? 0) * 100).toFixed(0)}%`.padStart(5).padEnd(8),
      `${s.behavioral.totalSteps}`.padStart(5).padEnd(7),
    ].join(" ");
    lines.push(`  ${row}`);

    // Add discovery details if available
    if (s.discovery) {
      lines.push(
        `    Vuln recall: ${(s.discovery.vulnerabilityRecall * 100).toFixed(0)}%  FP rate: ${(s.discovery.falsePositiveRate * 100).toFixed(0)}%  Missed: ${s.discovery.missedVulnerabilities.join(", ") || "none"}`,
      );
    }
  }

  // Regression
  if (result.regression) {
    lines.push("");
    lines.push(`REGRESSION vs ${result.regression.previousRunId}`);
    lines.push("-".repeat(40));
    const d = result.regression.overallDelta;
    lines.push(
      `  Overall delta: ${d > 0 ? "+" : ""}${d.toFixed(1)}`,
    );
    if (result.regression.significantChanges.length > 0) {
      for (const change of result.regression.significantChanges) {
        const arrow = change.direction === "improvement" ? "+" : "";
        lines.push(
          `  ${change.app} ${change.metric}: ${arrow}${change.delta.toFixed(1)} (${change.direction})`,
        );
      }
    } else {
      lines.push("  No significant changes.");
    }
  }

  lines.push("");
  lines.push(hr);
  return lines.join("\n");
}

export function generateJsonReport(result: SuiteResult): string {
  return JSON.stringify(result, null, 2);
}
